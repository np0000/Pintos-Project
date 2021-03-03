#include "vm/swap.h"


void swap_init() 
{
    global_swap_block = block_get_role(BLOCK_SWAP);
    lock_init(&blocks_lock);

    ASSERT(global_swap_block != NULL);
    blocks_bitmap = bitmap_create(block_size(global_swap_block));
    ASSERT(blocks_bitmap != NULL);
    bitmap_set_all(blocks_bitmap, false);
}


bool swap_in(struct sup_page_table_entry* page){
    if (global_swap_block == NULL || page == NULL || blocks_bitmap == NULL)
        return false;

    lock_acquire(&blocks_lock);
    
    ASSERT(page->frame_table_entry != NULL);
    uint8_t* frame = page->frame_table_entry->frame;
    
    /* Get the blocks' start index on the disk. */
    size_t start_index = page->block_start_index;
    
    if (start_index == INITIAL_STATUS)
        return false;
    
    for (int i = 0; i < BLOCKS_PER_PAGE; i++) 
        {
            /* Free the block. */
            bitmap_flip(blocks_bitmap, start_index + i);

            /* Read from disk to memory. */
            block_read(global_swap_block, start_index + i, frame + (i * BLOCK_SECTOR_SIZE));
        }
    /* Set back the index. */
    page->block_start_index = INITIAL_STATUS;
    lock_release(&blocks_lock);
    return true;
}

bool swap_out(struct sup_page_table_entry* page){
    if (global_swap_block == NULL || page == NULL || blocks_bitmap == NULL)
        return false;
    lock_acquire(&blocks_lock);

    /* Find enough block to store the page. */
    size_t start_index = bitmap_scan_and_flip(blocks_bitmap, 0, BLOCKS_PER_PAGE, false);
    if (start_index == BITMAP_ERROR)
        return false;
    page->block_start_index = start_index;

    uint8_t* frame = page->frame_table_entry->frame;
    
    /* Write from memory to disk. */
    for (int i = 0; i < BLOCKS_PER_PAGE; i++) 
        block_write(global_swap_block, start_index + i, frame + (i * BLOCK_SECTOR_SIZE));

    lock_release(&blocks_lock);
    return true;
}