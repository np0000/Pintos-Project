#include "vm/page.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "vm/swap.h"

#define STACK_MAX (1 << 23)

bool get_frame_for_page(struct sup_page_table_entry *p);


// init page table for given thread
// include malloc, should be freed when thread exits
void page_table_init(struct thread *t){
    t->page_table = (struct hash *)malloc(sizeof(struct hash));
    if (t->page_table == NULL){
        printf("Malloc fails in page_table_init.\n");
        return;
    }
    hash_init(t->page_table, page_table_hash_func, page_table_less_func, NULL);
}

// alloc a new page, if the given address is in an existing page, this function will return null
struct sup_page_table_entry* page_alloc(void *uaddr, bool writable, int page_type, struct file* file, 
                                                    off_t offset, uint32_t read_bytes, uint32_t zero_bytes){
    /* Get space to store page info. */
    struct sup_page_table_entry *p = malloc(sizeof(struct sup_page_table_entry));
    if (p == NULL){
        return NULL;
    }

    /* Initialize the page. */
    p->uaddr = pg_round_down(uaddr);
    p->owner_thread = thread_current();
    p->frame_table_entry = NULL;
    p->writable = writable;
    p->using = false;
    p->page_type = page_type;
    p->file = file;
    p->offset = offset;
    p->read_bytes = read_bytes;
    p->zero_bytes = zero_bytes;
    p->block_start_index = INITIAL_STATUS;
    
    struct hash_elem *e = hash_find(thread_current()->page_table, &p->elem);
    if (e != NULL){
        // page already exist
        free(p);
        return hash_entry(e, struct sup_page_table_entry, elem);
    }

    hash_insert(thread_current()->page_table, &p->elem);

    return p;
}



struct sup_page_table_entry* page_alloc_for_file (void *uaddr, bool writable, struct file* file, off_t offset, 
                                                    uint32_t read_bytes, uint32_t zero_bytes)
{
    return page_alloc(uaddr, writable, PAGE_FROM_FILE, file, offset, read_bytes, zero_bytes);
}

struct sup_page_table_entry* page_alloc_for_stack(void *uaddr, bool writable)
{
    return page_alloc(uaddr, writable, PAGE_FROM_SWAP, NULL, INITIAL_STATUS, INITIAL_STATUS, INITIAL_STATUS);
}

struct sup_page_table_entry* page_alloc_for_segment (void *uaddr, bool writable, struct file* file, off_t offset, 
                                                        uint32_t read_bytes, uint32_t zero_bytes)
{
    return page_alloc(uaddr, writable, PAGE_FROM_SEGM, file, offset, read_bytes, zero_bytes);
}

// free a page for others to use. 
void page_free(struct sup_page_table_entry *page){
    ASSERT(page != NULL);

    if (page->frame_table_entry != NULL){
        frame_lock(page->frame_table_entry);
        frame_free(page->frame_table_entry);
    }

    hash_delete(thread_current()->page_table, &page->elem);
    // clear from pintos page table
    pagedir_clear_page(thread_current()->pagedir, page->uaddr);

    free(page);
}

// evict a page
bool page_evict(struct sup_page_table_entry *page){
    // record if it is dirty, not known if it impacts swap yet
    struct thread* cur = thread_current();

    uint32_t addr = page->uaddr;

    bool flag = false;
    if (page->using || !page->writable)
        return false;
    
    bool dirty = pagedir_is_dirty (page->owner_thread->pagedir, page->uaddr);
    if (page->page_type == PAGE_FROM_SWAP)
    {
        flag = swap_out(page);
    }
        
    else if (page->page_type == PAGE_FROM_FILE)
    {
        if (dirty)
            flag = write_page_to_file(page);
        else
            flag = true;
    }
        
    
    if (flag)
    {
        // clear from pintos page table
        pagedir_clear_page(page->owner_thread->pagedir, page->uaddr);
        page->frame_table_entry = NULL;
    }
    return flag;
}

// free all pages in the page table, will NOT free frames
void page_table_free(){
    hash_destroy(thread_current()->page_table, page_table_destroy_func);
}

// if the faulted access should be granted, give current thread a new stack page
// if it's invalid access, return false. the page fault handler will take over.

bool page_handle_fault(void *faddr, void *esp){
    // check if the address is valid
    bool flag = true;
    if (faddr >= PHYS_BASE && !is_user_vaddr(faddr)){
        return false;
    }

    struct sup_page_table_entry p;
    p.uaddr = (void *) pg_round_down(faddr);

    // try to find an existing page
    struct hash_elem* elem = hash_find(thread_current()->page_table, &p.elem);
    if (elem != NULL){
        struct sup_page_table_entry *page = hash_entry(elem, struct sup_page_table_entry, elem);
        page->using = true;
        // already exist a page, get a frame for it,
        // and add page to pintos page table
        if (page->frame_table_entry == NULL)
        {
            if (!get_frame_for_page(page)){
                page->using = false;
                return false;
            }
        }

        if (page->page_type == PAGE_FROM_FILE)
        {
            flag = load_page_from_file(page);
        }
        else if (page->page_type == PAGE_FROM_SWAP)
        {
            flag = swap_in(page);
        }
        else
        {
            if (page->file != NULL)
                flag = load_page_from_file(page);

            page->page_type = PAGE_FROM_SWAP;
        }
        page->using = false;
    }
    else{
        
        /* No existing page
           Check if the access should be granted
           Check if the address is in the stack max capacity. */

        if (p.uaddr <= PHYS_BASE - STACK_MAX){
            return false;
        }

        // check if the address is within 32 bytes of stack pointer
        if (esp != NULL && faddr < (void *)esp - 32){
            return false;
        }

        // granted, alloc a new page for it
        struct sup_page_table_entry *page = page_alloc_for_stack(p.uaddr, true);
        page->using = true;
        // get a new frame
        if (!get_frame_for_page(page)){
            page->using = false;
            return false;
        }
        page->using = false;
        // page is added to pintos page table on alloc
    }

    return flag;
}


bool load_page_from_file (struct sup_page_table_entry* page)
{
    if (page == NULL || page->file == NULL || page->frame_table_entry == NULL)
        return false;

    uint8_t *frame = page->frame_table_entry->frame;

    lock_acquire(&lock_of_filesys);
    
    off_t offset = file_read_at(page->file, frame, page->read_bytes, page->offset);
    lock_release(&lock_of_filesys);
    memset(frame + page->read_bytes, 0, page->zero_bytes);
    return offset == page->read_bytes;
}

bool write_page_to_file (struct sup_page_table_entry* page)
{
    if (page == NULL || page->file == NULL || page->frame_table_entry == NULL)
        return false;
    
    uint8_t* frame = page->frame_table_entry->frame;
    lock_acquire(&lock_of_filesys);
    off_t offset = file_write_at(page->file, frame, page->read_bytes, page->offset);
    lock_release(&lock_of_filesys);

    return offset == page->read_bytes;

}

// get a frame. may require extra codes. now it just alloc a zero frame
bool get_frame_for_page(struct sup_page_table_entry *p){
    p->frame_table_entry = frame_alloc(p);
    if (p->frame_table_entry == NULL)
        return false;
    
    return true;
}

struct sup_page_table_entry* find_page_in_sup_table(void* addr)
{
    struct thread* cur = thread_current();
    struct sup_page_table_entry* target = NULL;
    struct sup_page_table_entry tmp;
    
    tmp.uaddr = pg_round_down(addr);

    struct hash_elem *e = hash_find(cur->page_table, &tmp.elem);

    if (e != NULL)
        target = hash_entry(e, struct sup_page_table_entry, elem);
    
    return target;
}

void page_table_destroy_func (struct hash_elem *e, void *aux){
    struct sup_page_table_entry *p = hash_entry(e, struct sup_page_table_entry, elem);
    
    struct frame_table_entry *f = p->frame_table_entry;


    bool dirty = pagedir_is_dirty (p->owner_thread->pagedir, p->uaddr);
    if (dirty && p->page_type == PAGE_FROM_FILE)
        write_page_to_file(p);     

    page_free(p);
}

unsigned page_table_hash_func(const struct hash_elem *e, void *aux){

    const struct sup_page_table_entry *p = hash_entry (e, struct sup_page_table_entry, elem);
    return ((uintptr_t) p->uaddr) >> 12;
}

bool page_table_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux){
    struct sup_page_table_entry *aa = hash_entry(a, struct sup_page_table_entry, elem);
    struct sup_page_table_entry *bb = hash_entry(b, struct sup_page_table_entry, elem);
    return aa->uaddr < bb->uaddr;
}
