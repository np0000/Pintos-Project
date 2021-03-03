#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "vm/page.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"

struct frame_table_entry {
    struct list_elem elem; //element for frame table
    struct lock lock;
    uint8_t *frame; // point to the data of the frame
    struct sup_page_table_entry *page; //corresponding page
};

struct list frame_table;
struct lock frame_table_lock;

void frame_table_init();
void frame_table_exit();

void frame_lock(struct frame_table_entry* frame_table_entry);
void frame_unlock(struct frame_table_entry* frame_table_entry);

struct frame_table_entry *frame_alloc(struct sup_page_table_entry *page);
void frame_free(struct frame_table_entry *frame_table_entry);

#endif