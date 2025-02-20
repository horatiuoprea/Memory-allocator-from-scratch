// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "block_meta.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MMAP_THRESHOLD 131072
#define MAP_ANONYMOUS 0x20
#define MAP_ANON MAP_ANONYMOUS

block_meta *head_of_heap = NULL, *head_of_mapped = NULL;

void coalesce(block_meta *start)
{
	if (start && start->next && start->status == 0 &&
		start->next->status == 0) {
		start->size = start->size + sizeof(block_meta) + start->next->size;
		start->next = start->next->next;
		if (start->next)
			start->next->prev = start;
	}
}

void coalesce_memory(void)
{
	block_meta *p = head_of_heap;

	while (p) {
		if (p->prev)
			coalesce(p->prev);
		p = p->next;
	}
}

block_meta *find(size_t size)
{
	coalesce_memory();
	size_t best_size = MMAP_THRESHOLD;
	block_meta *p = head_of_heap, *best = NULL;

	while (p) {
		if (p->status == 0 && p->size - size < best_size) {
			best_size = p->size - size;
			best = p;
		}
		p = p->next;
	}
	if (best)
		return best;
	return NULL;
}

void split(block_meta *start, size_t size)
{
	size = ALIGN(size);
	if (start->size >= size + sizeof(block_meta) + sizeof(char)) {
		block_meta *new = NULL;
		size_t rest;

		rest = start->size - size - sizeof(block_meta);
		new = (block_meta *)((char *)start + sizeof(block_meta) + size);
		new->size = rest;
		new->status = 0;
		new->next = start->next;
		new->prev = start;
		start->next = new;
		if (new->next)
			new->next->prev = new;
		start->size = size;
		start->status = 1;
	} else {
		start->status = 1;
	}
}

block_meta *add_heap(size_t size)
{
	size = ALIGN(size);
	block_meta *found = NULL;

	found = find(size);
	if (found) {
		split(found, size);
		return found;
	}
	block_meta *p = head_of_heap;

	while (p->next)
		p = p->next;
	if (p->status == 0) {
		sbrk(size - p->size);
		p->size = size;
		p->status = 1;
		return p;
	}
	block_meta *new = (block_meta *)sbrk(size + sizeof(block_meta));

	new->next = NULL;
	new->prev = NULL;
	new->size = size;
	new->status = 1;
	p->next = new;
	new->prev = p;
	return new;
}

void init_heap(void)
{
	head_of_heap = (block_meta *)sbrk(MMAP_THRESHOLD);
	head_of_heap->status = 0;
	head_of_heap->size = MMAP_THRESHOLD - sizeof(block_meta);
	head_of_heap->next = NULL;
	head_of_heap->prev = NULL;
}

block_meta *add_map(size_t size)
{
	size = ALIGN(size);
	size_t total = size + sizeof(block_meta);
	block_meta *zone = (block_meta *)mmap(NULL, total, PROT_READ | PROT_WRITE,
										  MAP_PRIVATE | MAP_ANON, -1, 0);
	if (zone == MAP_FAILED)
		return NULL;
	zone->next = NULL;
	zone->prev = NULL;
	zone->status = 2;
	zone->size = size;

	if (head_of_mapped == NULL) {
		head_of_mapped = zone;
	} else {
		block_meta *p = head_of_mapped;

		while (p->next)
			p = p->next;
		p->next = zone;
		zone->prev = p;
	}
	return zone;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	block_meta *mem_adr = NULL;

	if (size < MMAP_THRESHOLD) {
		if (head_of_heap == NULL)
			init_heap();
		mem_adr = add_heap(size);
	} else {
		mem_adr = add_map(size);
	}
	if (mem_adr)
		return (void *)((char *)mem_adr + sizeof(block_meta));
	return NULL;
}

block_meta *is_valid(void *ptr)
{
	block_meta *block_adr = (block_meta *)((char *)ptr - sizeof(block_meta));
	block_meta *p = head_of_heap;

	while (p) {
		if (p == block_adr)
			return block_adr;
		p = p->next;
	}
	p = head_of_mapped;
	while (p) {
		if (p == block_adr)
			return block_adr;
		p = p->next;
	}
	return NULL;
}

void os_free(void *ptr)
{
	block_meta *zone = is_valid(ptr);

	if (zone) {
		if (zone->status == 1) {
			zone->status = 0;
			coalesce_memory();
		} else {
			if (zone == head_of_mapped) {
				head_of_mapped = zone->next;
				if (zone->next)
					zone->next->prev = NULL;
				zone->next = NULL;
			} else {
				zone->prev->next = zone->next;
				if (zone->next)
					zone->next->prev = zone->prev;
				zone->next = NULL;
				zone->prev = NULL;
			}
			munmap(zone, zone->size + sizeof(block_meta));
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;

	size_t page_size = getpagesize();
	block_meta *mem_adr = NULL;
	void *addr = NULL;

	if (nmemb * size + sizeof(block_meta) < page_size) {
		if (head_of_heap == NULL)
			init_heap();
		mem_adr = add_heap(nmemb * size);
	} else {
		mem_adr = add_map(nmemb * size);
	}
	if (mem_adr) {
		addr = (void *)((char *)mem_adr + sizeof(block_meta));
		addr = memset(addr, 0, nmemb * size);
		return addr;
	}
	return NULL;
}

block_meta *extend_block(block_meta *start)
{
	size_t free_block = start->next->size;

	start->next = start->next->next;
	if (start->next)
		start->next->prev = start;
	start->size = start->size + sizeof(block_meta) + free_block;
	start->status = 1;
	return start;
}

void *os_realloc(void *ptr, size_t size)
{
	size = ALIGN(size);
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	block_meta *addr = (block_meta *)((char *)ptr - sizeof(block_meta));

	if (addr->status == 0)
		return NULL;

	if (addr->size > size) {
		if (addr->status == 1) {
			split(addr, size);
			return (void *)((char *)addr + sizeof(block_meta));
		}
		void *p = os_malloc(size);

		p = memcpy(p, ptr, size);
		os_free(ptr);
		return p;
	} else if (addr->size == size) {
		return ptr;
	}
	if (addr->status == 2) {
		void *p = os_malloc(size);

		p = memcpy(p, ptr, addr->size);
		os_free(ptr);
		return p;
	}
	coalesce_memory();
	if (addr->next) {
		if (addr->next->status == 0 &&
			addr->size + sizeof(block_meta) + addr->next->size >=
				size) {
			addr = extend_block(addr);
			split(addr, size);
			return (void *)((char *)addr + sizeof(block_meta));
		}
		void *p = os_malloc(size);

		p = memcpy(p, ptr, addr->size);
		os_free(ptr);
		return p;
	}
	sbrk(size - addr->size);
	addr->size = size;
	addr->status = 1;
	return (void *)((char *)addr + sizeof(block_meta));
}
