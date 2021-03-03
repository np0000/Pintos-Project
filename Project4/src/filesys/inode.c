#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCK_NUM      10
#define INDIRECT_BLOCK_NUM    1
#define DOUBLE_INDIRECT_NUM   1

#define INDIRECT_BLOCK_INDEX  10
#define DOUBLE_INDIRECT_INDEX 11

#define DIRECT_PER_INDIRECT   128
#define INDIRECT_PER_DOUBLE   128

#define DIRECT_BLOCK_SIZE     (BLOCK_SECTOR_SIZE * DIRECT_BLOCK_NUM)
#define INDIRECT_BLOCK_SIZE   (BLOCK_SECTOR_SIZE * DIRECT_PER_INDIRECT)
#define DOUBLE_INDIRECT_SIZE  (INDIRECT_PER_DOUBLE * INDIRECT_BLOCK_SIZE)


/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t blocks[12];          /* 10: 1: 1 = Direct: Indirect: Double */
    off_t length;                       /* File size in bytes. */
    unsigned is_dir;                    /* Is this inode a directory. */
    unsigned magic;                     /* Magic number. */

    uint32_t unused[113];               /* Not used. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
    
  };


struct indirect_block
  {
    block_sector_t direct_blocks[128];
  };


struct double_indirect_block
  {
    block_sector_t indirect_blocks[128];
  };

  
/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  block_sector_t sector = -1;
  if (pos > inode_length (inode))
    return -1;

  struct inode_disk *disk_inode = &inode->data;
  struct indirect_block *indirect = NULL;
  struct double_indirect_block *double_indirect = NULL;

  
  block_sector_t index = pos / BLOCK_SECTOR_SIZE;

  if (index < DIRECT_BLOCK_NUM)
    {
      sector = disk_inode->blocks[index];
    }
  else if (index < DIRECT_BLOCK_NUM + DIRECT_PER_INDIRECT)
    {
      index -= DIRECT_BLOCK_NUM;
      indirect = calloc (1, sizeof (struct indirect_block));

      if (indirect == NULL)
        return sector;

      cache_read_one_block (disk_inode->blocks[INDIRECT_BLOCK_INDEX], indirect);
      sector = indirect->direct_blocks[index];
      free (indirect);
    }
  else
    {
      index -= (DIRECT_BLOCK_NUM + DIRECT_PER_INDIRECT);

      /* Find the indirect block's index in double indirect block. */
      int ind_index = index / DIRECT_PER_INDIRECT;

      /* Find the direct block's index in indirect block. */
      int d_index = index % DIRECT_PER_INDIRECT;

      double_indirect = calloc (1, sizeof (struct double_indirect_block));
      
      if (double_indirect == NULL)
        return sector;

      cache_read_one_block (disk_inode->blocks[DOUBLE_INDIRECT_INDEX], double_indirect);
      
      indirect = calloc (1, sizeof (struct indirect_block));
      if (indirect == NULL)
        return sector;

      cache_read_one_block (double_indirect->indirect_blocks[ind_index], indirect);

      sector = indirect->direct_blocks[d_index];

      free (double_indirect);
      free (indirect);
    }
  return sector;
}


/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock lock_of_open_inodes;
/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&lock_of_open_inodes);
}


/* Add more sectors to the end of inode. */
bool 
inode_grow_sectors (struct inode_disk *disk_inode, off_t sectors)
{
  ASSERT (disk_inode != NULL);
  off_t created_sectors = 0;

  /* Grow direct blocks. */
  bool success = false;
  if (sectors != 0)
    {
      created_sectors = direct_block_grow (disk_inode, sectors);
      if (created_sectors == -1)
        {
          printf ("Create direct block failed.\n");
          return success;
        }
      sectors -= created_sectors;
    }

  /* Grow indirect blocks. */
  if (sectors != 0)
    {
      struct indirect_block *indirect = calloc (1, sizeof (struct indirect_block));
      block_sector_t ind_index = disk_inode->blocks[INDIRECT_BLOCK_INDEX];
      
      /* If ind_index == 0, the block doesn't exist. We need to create it first.
         If it exists, read it from disk directly. */
      if (ind_index == 0)
        {
          if (!free_map_allocate (1, &disk_inode->blocks[INDIRECT_BLOCK_INDEX]))
            return success;         
        }
      else
        {
          cache_read_one_block (ind_index, indirect);
        }
      created_sectors = indirect_block_grow (indirect, sectors);
      
      if (created_sectors == -1)
        {
          printf ("Create indirect block failed.\n");
          return success;
        }          

      cache_write_one_block (disk_inode->blocks[INDIRECT_BLOCK_INDEX], indirect);
      sectors -= created_sectors;
      free (indirect);
    }

  /* Grow double indirect blocks. */
  if (sectors != 0)
    {
      struct double_indirect_block *double_indirect = 
                                calloc (1, sizeof (struct double_indirect_block));
      block_sector_t d_ind_index = disk_inode->blocks[DOUBLE_INDIRECT_INDEX];

      /* If ind_index == 0, the block doesn't exist. We need to create it first.
         If it exists, read it from disk directly. */
      if (d_ind_index == 0)
        {
          if (!free_map_allocate (1, &disk_inode->blocks[DOUBLE_INDIRECT_INDEX]))
            return success;         
        }
      else
        {
          cache_read_one_block (d_ind_index, double_indirect);
        }

      created_sectors = double_indirect_block_grow (double_indirect, sectors);
      if (created_sectors == -1)
        {
          printf ("Create double indirect block failed.\n");
          return success;
        }          

      cache_write_one_block (disk_inode->blocks[DOUBLE_INDIRECT_INDEX], double_indirect);
      sectors -= created_sectors;
      free (double_indirect);
    }
  if (sectors == 0)
    success = true;
  return success;
}


bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;
  bool init = false;
  off_t created_sectors = 0;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir;
      success = inode_grow_sectors (disk_inode, sectors);
      /* Write disk_inode to disk. */
      cache_write_one_block (sector, disk_inode);
      free (disk_inode);
    }

  return success;
}


/* Grow expected number of sectors to the direct block. 
   Return the number of sectors it actually grows. */
off_t
direct_block_grow (struct inode_disk *disk_inode, off_t sectors)
{
  ASSERT (disk_inode != NULL);
  static char zeros[BLOCK_SECTOR_SIZE];
  if (sectors == 0 || disk_inode->blocks[DIRECT_BLOCK_NUM - 1] != 0)
    return 0;
  
  /* Find the free place. */
  off_t begin = DIRECT_BLOCK_NUM;
  for (int i = 0; i < DIRECT_BLOCK_NUM; i++)
    {
      if (disk_inode->blocks[i] == 0) 
        {
          begin = i;
          break;
        }
    }

  off_t remained = DIRECT_BLOCK_NUM - begin;
  off_t to_create = remained >= sectors ? sectors : remained;

  block_sector_t sector_idx;
  for (int i = begin; i < begin + to_create; i++) {
    
    if (!(free_map_allocate (1, &sector_idx)))
      return -1;
    
    disk_inode->blocks[i] = sector_idx;
    cache_write_one_block (sector_idx, zeros);
  }
  
  return to_create;
}


/* Grow expected number of sectors to the indirect block. 
   Return the number of sectors it actually grows. */
off_t
indirect_block_grow (struct indirect_block* indirect, off_t sectors)
{
  ASSERT (indirect != NULL);

  /* No sectors need to be add or this indirect block is full. */
  if (sectors == 0 || indirect->direct_blocks[DIRECT_PER_INDIRECT - 1] != 0)
    return 0;
  
  /* Find the free place. */
  off_t begin = DIRECT_PER_INDIRECT;
  for (int i = 0; i < DIRECT_PER_INDIRECT; i++)
    {
      if (indirect->direct_blocks[i] == 0) 
        {
          begin = i;
          break;
        }
    }
  
  off_t remained = DIRECT_PER_INDIRECT - begin;
  off_t to_create = remained >= sectors ? sectors : remained;
  static char zeros[BLOCK_SECTOR_SIZE];

  block_sector_t sector_idx;
  for (int i = begin; i < begin + to_create; i++)
    {
      if (!free_map_allocate (1, &sector_idx))
        return -1;
      indirect->direct_blocks[i] = sector_idx;
      cache_write_one_block (sector_idx, zeros);

    }

  return to_create;
}

/* Grow expected number of sectors to the double indirect block. 
   Return the number of sectors it actually grows. */
off_t
double_indirect_block_grow (struct double_indirect_block* double_block, off_t sectors)
{
  ASSERT (double_block != NULL);
  off_t to_create = sectors;
  int index = 0;
  static char zeros[BLOCK_SECTOR_SIZE];
  struct indirect_block *indirect = NULL;

  if (sectors == 0)
    return 0;
  
  while (to_create > 0 && index < INDIRECT_PER_DOUBLE)
    {
      off_t created = 0;
      block_sector_t ind_sector = double_block->indirect_blocks[index];
      indirect = calloc (1, sizeof (struct indirect_block));
      if (ind_sector == 0)
        {
          if (!free_map_allocate (1, &ind_sector))
            {
              printf ("No free sector.\n");
              return -1;
            }

          double_block->indirect_blocks[index] = ind_sector;
        }
      else
        {
          cache_read_one_block (ind_sector, indirect);
        }
      
      created = indirect_block_grow (indirect, to_create);
      cache_write_one_block (ind_sector, indirect);

      free (indirect);
      indirect = NULL;

      to_create -= created;
      index++;
    }
  return sectors;

}


/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  lock_acquire (&lock_of_open_inodes);
  
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          lock_release (&lock_of_open_inodes);
          return inode; 
        }
    }
  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read_one_block (inode->sector, &inode->data);
  lock_release (&lock_of_open_inodes);

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}


/* Release all direct blocks, indirect blocks and double indirect block in
   free map. Also release the inode. */
void 
remove_one_inode (struct inode *inode)
{
  struct inode_disk* disk_inode = &inode->data;
  block_sector_t sectors = bytes_to_sectors (disk_inode->length);
  block_sector_t sector = inode->sector;
  block_sector_t ind_sector = disk_inode->blocks[INDIRECT_BLOCK_INDEX];
  block_sector_t d_ind_sector = disk_inode->blocks[DOUBLE_INDIRECT_INDEX];
  struct double_indirect_block *double_indirect = NULL;

  free_map_release (inode->sector, 1);

  /* Release all direct blocks. */
  for (int i = 0; i < sectors; i++)
    {
      sector = byte_to_sector(inode, i * BLOCK_SECTOR_SIZE);
      free_map_release (sector, 1);
    }

  /* Release the indirect blocks. */
  if (ind_sector != 0)
    {
      free_map_release (ind_sector, 1);
    }

  /* Release the double indirect blocks and indirect blocks. */
  if (d_ind_sector != 0)
    {
      double_indirect = calloc (1, sizeof (struct double_indirect_block));
      cache_read_one_block (d_ind_sector, double_indirect);

      for (int i = 0; i < INDIRECT_PER_DOUBLE; i++)
        {
          int sector_idx = double_indirect->indirect_blocks[i];

          if (sector_idx != 0)
            free_map_release (sector_idx, 1);
        }
      free_map_release (d_ind_sector, 1);
      free (double_indirect);
      double_indirect = NULL;
    }
}


/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  
  lock_acquire (&lock_of_open_inodes);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          remove_one_inode (inode);
        }

      free (inode); 
    }
  lock_release (&lock_of_open_inodes);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  if (offset > inode_length (inode))
    return 0;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      struct inode_disk *disk_inode = &inode->data;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      
      cache_read_from (sector_idx, buffer + bytes_read, chunk_size, sector_ofs);;

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
      
      /* Read ahead. */
      int sector_to_read = byte_to_sector (disk_inode, offset);
      
      if (sector_to_read != -1)
        cache_add_read_ahead_elem (sector_to_read);
    }

  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  bool grow = false;

  if (inode->deny_write_cnt)
    return 0;

  off_t file_length = inode_length (inode);
  off_t ori_sectors = bytes_to_sectors (file_length);
  off_t cur_sectors = bytes_to_sectors (offset + size);
  if (cur_sectors > ori_sectors)
    {
      off_t to_create = cur_sectors - ori_sectors;
      grow = inode_grow_sectors (&inode->data, to_create);

      if (!grow)
        return 0;
      cache_write_one_block (inode->sector, &inode->data);
    }

  if (offset + size > file_length)
    {
      inode->data.length = size + offset;
      cache_write_one_block (inode->sector, &inode->data);
    }
  
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;
      if (chunk_size <= 0)
        break;

      cache_write_at (sector_idx, buffer + bytes_written, chunk_size, sector_ofs);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }


  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  if (inode->deny_write_cnt <= 0){
    inode->deny_write_cnt = 0;
    return;
  }
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}


bool inode_is_dir(struct inode *inode){
  return inode->data.is_dir;
}

bool inode_is_open(struct inode *inode){
  if (inode->open_cnt > 0){
    //printf("open count: %d\n", inode->open_cnt);
    return true;
  }
  else{
    return false;
  }
}