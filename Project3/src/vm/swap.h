#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "vm/page.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"

#define BLOCKS_PER_PAGE 8                           /* PGSIZE / BLOCK_SECTOR_SIZE */

static struct block* global_swap_block;             /* Block used for swap. */
struct lock blocks_lock;                            /* Lock the bitmap. */
struct bitmap* blocks_bitmap;                       /* Record which block is free. */

void swap_init();
bool swap_in(struct sup_page_table_entry* page);    /* Swap from disk to memory. */
bool swap_out(struct sup_page_table_entry* page);   /* Swap from memory to disk. */

#endif