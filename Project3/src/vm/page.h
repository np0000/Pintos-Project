#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


#define PAGE_FROM_FILE 0
#define PAGE_FROM_SWAP 1
#define PAGE_FROM_SEGM 2

struct sup_page_table_entry {
    void *uaddr;                                /* user page's virtual address. */
    struct thread *owner_thread;                /* The entry's owner thread. */
    struct frame_table_entry *frame_table_entry;/* The page's corresponding frame entry. */
    struct hash_elem elem;                      /* Hash element. */

    bool writable;                              /* Whether the page is writable. */
    bool using;                                 /* Whether the page is using. */
    int page_type;                              /* 0 for file, 1 for swap, 2 for segment. */

    struct file *file;                          /* The page's mapped file. */
    off_t offset;                               /* The starting offset in the file. */
    uint32_t read_bytes;                        /* How many bytes are read. */
    uint32_t zero_bytes;                        /* How many zero bytes at the end. */
    int block_start_index;                      /* Start index in swap disk. */
    struct list_elem l_elem;                    /* List element. */
};

void page_table_init(struct thread *t);

void page_free(struct sup_page_table_entry *page);

void page_table_free();

bool page_evict(struct sup_page_table_entry *page);

bool page_handle_fault(void *faddr, void *esp);

struct sup_page_table_entry* page_alloc(void *uaddr, bool writable, int page_type, struct file* file, 
                                                    off_t offset, uint32_t read_bytes, uint32_t zero_bytes);
                                                    
struct sup_page_table_entry* page_alloc_for_stack(void *uaddr, bool writable);
struct sup_page_table_entry* page_alloc_for_file (void *uaddr, bool writable, struct file* file, 
                                                    off_t offset, uint32_t read_bytes, uint32_t zero_bytes);

struct sup_page_table_entry* page_alloc_for_segment (void *uaddr, bool writable, struct file* file, 
                                                        off_t offset, uint32_t read_bytes, uint32_t zero_bytes);

// functions to pass into hash
unsigned page_table_hash_func(const struct hash_elem *e, void *aux);
bool page_table_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux);
void page_table_destroy_func (struct hash_elem *e, void *aux);
struct sup_page_table_entry* find_page_in_sup_table(void* addr);

bool load_page_from_file (struct sup_page_table_entry* page);
bool write_page_to_file (struct sup_page_table_entry* page);

#endif