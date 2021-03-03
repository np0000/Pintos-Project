#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H


#include "lib/stdbool.h"
#include "lib/kernel/list.h"
#include "devices/block.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/thread.h"

#define CACHE_BLOCK_NUM 64          /* Total 64 cache blocks. */
#define PERIODIC_WRITE_TIME 500     /* Write behind period. */

struct cache_block
	{
		uint8_t data[BLOCK_SECTOR_SIZE]; 		/* One block contains 512 bytes data. */
		block_sector_t sector_idx;             	/* Data from sector_idx in disk. */
		bool used;								/* Whether this cache block is used. */
		bool dirty;                        		/* Dirty bit. */
		bool accessed;							/* Access bit, for clock policy. */
		struct lock lock_of_cache_block;		/* Single cache block lock. */
	};

struct read_ahead_elem
	{
		block_sector_t sector_idx;				/* Disk sector_idx to read. */
		struct list_elem elem;					/* List elem. */
	};

/* Buffer cache. Total 64 cache blocks. */
struct cache_block* buffer_cache[CACHE_BLOCK_NUM];

/* Record sector_idx to read. */
struct list read_ahead_list;

/* Whole buffer cache lock. */
struct lock lock_of_buffer_cache;

/* read_ahead_list lock. */
struct lock lock_of_read_ahead;

/* Condition variable to notice read_ahead_thread. */
struct condition read_ahead_cond;

/* Find cache whether contain this sector's data. If not return null, else return a pointer to the cache block. */
struct cache_block *cache_find_block (block_sector_t sector);

/* If buffer cache is full, evict one cache block. Use clock policy. */
struct cache_block *cache_evict ();

/* Return a pointer to the cache block which contains sector's data. 
   If cache doesn't have the sector's data, read it from disk first.
   If return null, there's an error. */
struct cache_block *cache_get_block (block_sector_t sector);

/* Get the cache block with sector's data and read size bytes data from 
   data + offset to buffer. */ 
void cache_read_from (block_sector_t sector, void *buffer, off_t size, off_t offset);

/* Get the cache block with sector's data and write size bytes data to 
   data + offset from buffer. */ 
void cache_write_at (block_sector_t sector, void *buffer, off_t size, off_t offset);

/* Read the whole sector to buffer. */
void cache_read_one_block (block_sector_t sector, void *buffer);

/* Write the whole sector from buffer. */
void cache_write_one_block (block_sector_t sector, void *buffer);

/* Write all dirty cache block to disk. */
void cache_write_back_all ();

/* Add a sector index to read_ahead_list. */
void cache_add_read_ahead_elem (block_sector_t sector);

/* Write all dirty cache block to disk periodically. */
static void cache_write_behind (void *aux UNUSED);

/* Read the sectors in read_ahead_list to cache. */
static void cache_read_ahead (void *aux UNUSED);

#endif /* filesys/cache.h */