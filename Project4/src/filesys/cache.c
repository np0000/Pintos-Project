#include "filesys/cache.h"


/* Cache Initialize. */

int clock_hand;


/* Initialize buffer cache. */
void 
cache_init ()
{
  clock_hand = 0;

  /* Init each cache block. */
  for (int i = 0; i < CACHE_BLOCK_NUM; i++)
    {
      buffer_cache[i] = malloc (sizeof (struct cache_block));
      buffer_cache[i]->sector_idx = INITIAL_STATUS;
      buffer_cache[i]->used = false;
      buffer_cache[i]->dirty = false;
      buffer_cache[i]->accessed = false;
      lock_init(&buffer_cache[i]->lock_of_cache_block);
    }
  
  list_init (&read_ahead_list);
  lock_init (&lock_of_buffer_cache);
  lock_init (&lock_of_read_ahead);
  cond_init (&read_ahead_cond);

  thread_create ("read_ahead_thread", PRI_DEFAULT, cache_read_ahead, NULL);
  thread_create ("write_behind_thread", PRI_DEFAULT, cache_write_behind, NULL);
  
}

/* Find whether disk's sector is already in the buffer cache. */ 
struct cache_block *
cache_find_block (block_sector_t sector)
{
  struct cache_block * block = NULL;
  for (int i = 0; i < CACHE_BLOCK_NUM; i++)
    {
      if (buffer_cache[i]->sector_idx == sector)
        {
          block = buffer_cache[i];
          break;
        }
    }
  return block;
}

/* Cache evict policy. Here we use clock policy. */
struct cache_block *
cache_evict ()
{
  struct cache_block *block = NULL;
  struct cache_block *ptr = NULL;

  /* Find the block to evict. */
  while (true)
    {
      ptr = buffer_cache[clock_hand];
      clock_hand = (clock_hand + 1) % CACHE_BLOCK_NUM;

      if (lock_try_acquire (&ptr->lock_of_cache_block))
        {
          if (ptr->accessed)
            {
              ptr->accessed = false;
              lock_release (&ptr->lock_of_cache_block);
            }
          else
            {
              block = ptr;
              break;
            }
        }
    }

    /* If dirty, write back. */
    if (block->dirty)
      {
        block_write (fs_device, block->sector_idx, block->data);
        block->dirty = false;
      }

    lock_release (&block->lock_of_cache_block);

    return block;
}

/* Return a pointer to the cache block containing the disk sector's data.
   If it is already in the cache, return it directly. If it is not in the cache, read it from disk. */
struct cache_block *
cache_get_block (block_sector_t sector)
{
  struct cache_block *block = NULL;
  struct cache_block *last_block = buffer_cache[CACHE_BLOCK_NUM - 1];
  block = cache_find_block (sector);

  if (block == NULL)
    {
      /* Still has cache block never been used. */
      if (!last_block->used)
        {
          for (int i = 0; i < CACHE_BLOCK_NUM; i++)
            {
              if (!buffer_cache[i]->used)
                {
                  block = buffer_cache[i];
                  block->used = true;
                  break;
                }
            }
        }
      else 
        block = cache_evict ();

      if (block == NULL)
        {
          printf ("Failed to get one cache block.\n");
          return block;
        }

      block->sector_idx = sector;
      block_read (fs_device, sector, block->data);
    }

  block->accessed = true;

  return block;
}


/* Read from a cache block to buffer. */
void 
cache_read_from (block_sector_t sector, void *buffer, off_t size, off_t offset)
{
  struct cache_block* block = NULL;

  lock_acquire (&lock_of_buffer_cache);
  block = cache_get_block (sector);

  if (block == NULL)
    {
      printf ("Failed to get expected block when read");
      return;
    }

  /* For read ahead using, buffer can be null. */
  if (buffer != NULL)
    memcpy (buffer, block->data + offset, size);

  lock_release (&lock_of_buffer_cache);
}


/* Write from memory to cache. */
void
cache_write_at (block_sector_t sector, void *buffer, off_t size, off_t offset)
{
  struct cache_block* block = NULL;

  lock_acquire (&lock_of_buffer_cache);
  block = cache_get_block (sector);

  if (block == NULL)
    {
      printf ("Failed to get expected block when read");
      return;
    }

  memcpy(block->data + offset, buffer, size);
  block->dirty = true;
  lock_release (&lock_of_buffer_cache);
}


/* Read a whole block from sector to buffer. */
void 
cache_read_one_block (block_sector_t sector, void *buffer)
{
  cache_read_from (sector, buffer, BLOCK_SECTOR_SIZE, 0);
}

/* Write a whole block from buffer to sector. */
void 
cache_write_one_block (block_sector_t sector, void *buffer)
{
  cache_write_at (sector, buffer, BLOCK_SECTOR_SIZE, 0);
}


/* Write back all dirty cache block back to disk. */
void 
cache_write_back_all ()
{
  struct cache_block* block = NULL;
  lock_acquire (&lock_of_buffer_cache);

  for (int i = 0; i < CACHE_BLOCK_NUM; i++)
    {
      block = buffer_cache[i];
      lock_acquire (&block->lock_of_cache_block);

      if (block->used && block->dirty)
        {
          block_write (fs_device, block->sector_idx, block->data);
          block->dirty = false;
        }

      block->accessed = true;
      lock_release (&block->lock_of_cache_block);
    }

  lock_release (&lock_of_buffer_cache);
}


/* Use other's code for ref. */
/* Add a read ahead element to represent next sector to be read ahead. */
void 
cache_add_read_ahead_elem (block_sector_t sector)
{
  struct read_ahead_elem *read = malloc (sizeof (struct read_ahead_elem));
  read->sector_idx = sector;

  lock_acquire(&lock_of_read_ahead);
  list_push_back(&read_ahead_list, &read->elem);
  cond_signal(&read_ahead_cond, &lock_of_read_ahead);
  lock_release(&lock_of_read_ahead);

}

/* Read ahead. */
static void 
cache_read_ahead (void *aux UNUSED)
{
    struct read_ahead_elem *read;

    while(true)
      {
        lock_acquire (&lock_of_read_ahead);
        
        while(list_empty (&read_ahead_list))
          {
            cond_wait (&read_ahead_cond, &lock_of_read_ahead);
          }

        read = list_entry(list_pop_front(&read_ahead_list), 
                          struct read_ahead_elem, elem);
        lock_release(&lock_of_read_ahead);

        cache_read_one_block(read->sector_idx, NULL);
        free(read);
      }
}

/* Write behind periodically. */
static void 
cache_write_behind (void *aux UNUSED)
{
  while (true)
  {
    timer_sleep (PERIODIC_WRITE_TIME);
    cache_write_back_all();
  }
}
