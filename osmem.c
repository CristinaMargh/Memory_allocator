// SPDX-License-Identifier: BSD-3-Clause
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include "printf.h"
#include "../utils/block_meta.h"
#include "../utils/osmem.h"


#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define MMAP_THRESHOLD		(128 * 1024)
#define SIZE (ALIGN(sizeof(struct block_meta)))
#define PAGE 4096

// We consider the first block of the future block-list
struct block_meta *first;
// Used to see if it is the first allocation on the heap or not
int which_time;
// Add at the end of the list the blocks allocated with mmap
void expand_list_mapped(struct block_meta *block)
{
	if (first == NULL) {
		first = block;
		return;
		}
	struct block_meta *new = first;
	// We iterate through the list until the end
	while (new->next)
		new = new->next;
	new->next = block;
	block->prev = new;
	block->next = NULL;
}
// Add a block at the beginning of the list
void expand_list_alloc(struct block_meta *block)
{
	struct block_meta *new = first;

	if (first == NULL) {
		first = block;
		return;
	}
	// We want the blocks with MAPPED status at the end of the list,
	// so we check the status of the first one.
	if (first->status == STATUS_MAPPED) {
		block->next = first;
		first->prev = block;
		first = block;
		return;
	}
	while (new->next) {
		if (new->next->status == STATUS_MAPPED)
			break;
		new = new->next;
	}
	block->next = new->next;
	block->prev = new;
	if (block->next)
		block->next->prev = block;
	new->next = block;
}
// Used for the free function
void remove_from_list(struct block_meta *block)
{
	if (!first->next) {
		first = NULL;
		return;
	}
	struct block_meta *new = first;

	if (new == block) {
		new = new->next;
		new->prev = NULL;
		first = new;
	}
	// Iterate through the list
	while (new->next && new->next != block)
		new = new->next;
	new->next = block->next;
	if (new->next)
		new->next->prev = new;
}
// Used to truncate blocks to the required size
struct block_meta *split(struct block_meta *block, size_t size)
{
	if (ALIGN(block->size) - ALIGN(size) < SIZE + 1)
		return block;

	struct block_meta *new = (struct block_meta *)((char *)block + ALIGN(size) + SIZE);
	//Initializations for the new block
	new->status = STATUS_FREE;
	new->next = block->next;
	new->size = ALIGN(block->size) - ALIGN(size) - SIZE;
	new->prev = block;

	block->size = ALIGN(size);
	if (block->next)
		block->next->prev = new;
	block->next = new;
	block->status = STATUS_ALLOC;
	return block;
}
// Function used to find and reuse free blocks with the size closer to the one we need
struct block_meta *find_best(size_t size)
{
	struct block_meta *curr = first;
	// We need a big number to start the comparations of the sizes.
	size_t min = ULLONG_MAX;
	struct block_meta *best = NULL;

	while (curr) {
		if (curr->status == STATUS_FREE && ALIGN(curr->size) >= ALIGN(size) && ALIGN(curr->size) < min) {
			min = ALIGN(curr->size);
			best = curr;
		}
		curr = curr->next;
	}
	return best;
}

void *os_malloc(size_t size)
{
	void *p;

	if (size == 0)
		return NULL;
	// In this case we check if the size is bigger than the MMAP_THRESHOLD value, so we use mmap
	if (ALIGN(size) + SIZE >= MMAP_THRESHOLD) {
		p = mmap(NULL, ALIGN(size) + SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(p == (void *)(-1), "mmap() failed!\n");
		struct block_meta *block = (struct block_meta *)p;

		block->next = NULL;
		block->prev = NULL;
		block->size = size;
		block->status = STATUS_MAPPED;
		expand_list_mapped(block);
		return (void *)(((char *)block) + SIZE);
	}
	if (which_time == 0) {
		// Heap preallocation
		p = sbrk(MMAP_THRESHOLD);
		DIE(p == (void *)(-1), "sbrk() failed!\n");
		struct block_meta *block = (struct block_meta *)p;

		block->status = STATUS_ALLOC;
		block->size = MMAP_THRESHOLD - SIZE;
		block->next = NULL;
		block->prev = NULL;
		expand_list_alloc(block);
		which_time = 1;
		return (void *)(((char *)block) + SIZE);
	}
	// We go through the list and join together the blocks that have status free
	struct block_meta *curr_block = first;

	while (curr_block && curr_block->next) {
		if (curr_block->status == STATUS_FREE && curr_block->next->status == STATUS_FREE) {
			curr_block->size +=  SIZE + curr_block->next->size;
			struct block_meta *next = curr_block->next->next;

			curr_block->next = next;
			if (next)
				next->prev = curr_block;
		} else {
			curr_block = curr_block->next;
		}
	}
	// Find best fitting free block
	struct block_meta *best = find_best(size);

	if (best) {
		best = split(best, size);
		best->status = STATUS_ALLOC;
		return (void *)((char *)best + SIZE);
	}
	curr_block = first;
	while (curr_block->next && (curr_block->status == STATUS_ALLOC || curr_block->status == STATUS_FREE))
		curr_block = curr_block->next;
	if (curr_block->status == STATUS_FREE) {
		sbrk(ALIGN(size) - ALIGN(curr_block->size));
		curr_block->size = size;
		curr_block->status = STATUS_ALLOC;
		return (void *)((char *)curr_block + SIZE);
		}
	struct block_meta *new = sbrk(ALIGN(size) + SIZE);

	DIE(new == (void *)(-1), "sbrk() failed!\n");
	new->prev = NULL;
	new->next = NULL;
	new->size = size;
	new->status = STATUS_ALLOC;
	expand_list_alloc(new);
	return (void *)((char *)new + SIZE);
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	// I extract the block that I want to release.
	struct block_meta *block = (struct block_meta *)((char *)ptr - SIZE);

	if (block->status == STATUS_ALLOC)
		block->status = STATUS_FREE;
	if (block->status == STATUS_MAPPED) {
		remove_from_list(block);
		int ret;

		ret = munmap(block, ALIGN(block->size) + SIZE);
		// Checking the error code returned by munmap syscall.
		DIE(ret == -1, "munmap() failed!\n");
	}
}
// Similar to malloc, only that at the end we use memset
// for 0 initialization
void *os_calloc(size_t nmemb, size_t size)
{
	void *p;

	if (size == 0 || nmemb == 0)
		return NULL;
	// In this case we check if the size is bigger than the PAGE value, so we use mmap
	if (ALIGN(size * nmemb) + SIZE >= PAGE) {
		p = mmap(NULL, ALIGN(size * nmemb) + SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(p == (void *)(-1), "mmap() failed!\n");
		struct block_meta *block = (struct block_meta *)p;

		block->next = NULL;
		block->prev = NULL;
		block->size = ALIGN(size * nmemb);
		block->status = STATUS_MAPPED;
		expand_list_mapped(block);
		memset((void *)(((char *)block) + SIZE), 0, nmemb * size);
		return (void *)(((char *)block) + SIZE);
	}
	if (which_time == 0) {
		p = sbrk(MMAP_THRESHOLD);
		DIE(p == (void *)(-1), "sbrk() failed!\n");
		struct block_meta *block = (struct block_meta *)p;

		block->status = STATUS_ALLOC;
		block->size = PAGE - SIZE;
		block->next = NULL;
		block->prev = NULL;
		expand_list_alloc(block);
		which_time = 1;
		memset((void *)(((char *)block) + SIZE), 0, nmemb * size);
		return (void *)(((char *)block) + SIZE);
	}
	// We go through the list and join together the blocks that have status free
	struct block_meta *curr_block = first;

	while (curr_block && curr_block->next) {
		if (curr_block->status == STATUS_FREE && curr_block->next->status == STATUS_FREE) {
			curr_block->size += SIZE + ALIGN(curr_block->next->size);
			struct block_meta *next = curr_block->next->next;

			curr_block->next = next;
			if (next)
				next->prev = curr_block;
		} else {
			curr_block = curr_block->next;
		}
	}
	// Find best Block
	struct block_meta *best = find_best(size * nmemb);

	if (best) {
		split(best, size * nmemb);
		best->status = STATUS_ALLOC;
		memset((void *)(((char *)best) + SIZE), 0, nmemb * size);
		return (void *)((char *)best + SIZE);
	}
	curr_block = first;
	while (curr_block->next && (curr_block->status == STATUS_FREE || curr_block->status == STATUS_ALLOC))
		curr_block = curr_block->next;
	if (curr_block->status == STATUS_FREE) {
		sbrk(ALIGN(size * nmemb) -  ALIGN(curr_block->size));
		curr_block->size = ALIGN(size * nmemb);
		curr_block->status = STATUS_ALLOC;
		memset((void *)(((char *)curr_block) + SIZE), 0, nmemb * size);
		return (void *)((char *)curr_block + SIZE);
	}
	struct block_meta *new = sbrk(ALIGN(size * nmemb) + SIZE);

	DIE(new == (void *)(-1), "sbrk() failed!\n");
	new->prev = NULL;
	new->next = NULL;
	new->size = ALIGN(size * nmemb);
	new->status = STATUS_ALLOC;
	expand_list_alloc(new);
	memset((void *)(((char *)new) + SIZE), 0, nmemb * size);
	return (void *)((char *)new + SIZE);
}

void *os_realloc(void *ptr, size_t size)
{
	struct block_meta *block = (struct block_meta *)((char *)ptr - SIZE);
	// Initial checks
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	if (block->status == STATUS_FREE)
		return NULL;

	if (ALIGN(size) == ALIGN(block->size))
		return ptr;

	if (block->status == STATUS_MAPPED) {
		void *ret = os_malloc(size);

		if (ALIGN(block->size) <= ALIGN(size))
			memcpy(ret, ptr, ALIGN(block->size));
		else
			memcpy(ret, ptr, ALIGN(size));
		os_free(ptr);
		return ret;
	}
	if (ALIGN(size) + SIZE >= MMAP_THRESHOLD) {
		void *ret = os_malloc(size);

		if (ALIGN(block->size) <= ALIGN(size))
			memcpy(ret, ptr, ALIGN(block->size));
		else
			memcpy(ret, ptr, ALIGN(size));
		os_free(ptr);
		return ret;
	}

	if (ALIGN(size) < ALIGN(block->size)) {
		block = split(block, size);
		return (void *)((char *)block + SIZE);
	}
	struct block_meta *last_one = first;
	// Last block
	while (last_one->next && (last_one->status == STATUS_FREE || last_one->status == STATUS_ALLOC))
		last_one = last_one->next;

	if (block == last_one) {
		sbrk(ALIGN(size) - ALIGN(last_one->size));
		last_one->size = ALIGN(size);
		return (void *)(((char *)last_one) + SIZE);
	}
	// Coalesce
	struct block_meta *curr_block = first;

	while (curr_block && curr_block->next) {
		if (curr_block->status == STATUS_FREE && curr_block->next->status == STATUS_FREE) {
			curr_block->size +=  SIZE + curr_block->next->size;
			struct block_meta *next = curr_block->next->next;

			curr_block->next = next;
			if (next)
				next->prev = curr_block;
		} else {
			curr_block = curr_block->next;
		}
	}
	// We join the next blocks if they are free
	struct block_meta *new = block->next;

	if (new && new->status == STATUS_FREE) {
		block->size += new->size + SIZE;
		block->next = new->next;
		if (block->next)
			block->next->prev = block;
	}

	if (ALIGN(size) <= ALIGN(block->size)) {
		block = split(block, size);
		return (void *)((char *)block + SIZE);
	}
		void *ret = os_malloc(size);

		memcpy(ret, ptr, ALIGN(block->size));
		os_free(ptr);
		return ret;
}
