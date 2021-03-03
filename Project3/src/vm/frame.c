#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "threads/loader.h"
#include "threads/synch.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

#define TABLESIZE 256

struct frame_table_entry *frames_malloc;

static bool install_page (void *upage, void *kpage, bool writable);

struct list_elem* clock;



void frame_table_init(){
    list_init(&frame_table);
    lock_init(&frame_table_lock);

    void* init_frame = NULL;

    //malloc space to store frame table entries
    frames_malloc = malloc(sizeof(struct frame_table_entry) * TABLESIZE);
    if (frames_malloc == NULL){
        printf("malloc failes in frame_table_init\n");
    }

    lock_acquire(&frame_table_lock);
    for (int i = 0; i < TABLESIZE; i++){
        // if get page fail, continue with pages we have
        init_frame = palloc_get_page (PAL_USER | PAL_ZERO);
        if (init_frame == NULL){
            break;
        }

        //init frame table entry
        struct frame_table_entry *f = frames_malloc + i;
        f->frame = init_frame;
        f->page = NULL;
        lock_init(&f->lock);
        list_push_back(&frame_table, &f->elem);
    }
    lock_release(&frame_table_lock);

    // init clock to the first element
    clock = list_begin(&frame_table);
}

void frame_table_exit(){
    free(frames_malloc);
}

// get a frame for given page.
// currently panic if no free frame to use.
struct frame_table_entry* frame_alloc(struct sup_page_table_entry *page){
    lock_acquire(&frame_table_lock);
    // try to find a free frame
    struct list_elem *e;
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
    {
        struct frame_table_entry *f = list_entry (e, struct frame_table_entry, elem);
        bool suc = lock_try_acquire(&f->lock);
        if (suc == false){
            continue;
        }
        if (f->page == NULL){
            f->page = page;
            
            // add page into pagedir
            if (!install_page(page->uaddr, f->frame, page->writable)){
                lock_release(&f->lock);
                lock_release(&frame_table_lock);
                return NULL;
            }

            lock_release(&f->lock);
            lock_release(&frame_table_lock);
            return f;
        }

        lock_release(&f->lock);
    }

    // can not find a free frame
    // evict one page
    for (int i = 0; i < TABLESIZE; i++){
        // frame is busy, next

        clock = list_next(clock);
        if (clock == list_end(&frame_table))
            clock = list_begin(&frame_table);

        struct frame_table_entry *f = list_entry(clock, struct frame_table_entry, elem);
        if (!lock_try_acquire(&f->lock)){
            continue;
        }

        // frame is not busy
        if (!page_evict(f->page)){
            lock_release(&f->lock);
            continue;
        }
        lock_release(&f->lock);
        f->page = page;

        lock_release(&frame_table_lock);
        if (!install_page(page->uaddr, f->frame, page->writable)){
            return NULL;
        }
        return f;
    }
    
    lock_release(&frame_table_lock);
    return NULL;
}

// free a frame
// the lock of the frame should be held by current thread when calling this
void frame_free(struct frame_table_entry *frame_table_entry){
    ASSERT(lock_held_by_current_thread(&frame_table_entry->lock));

    // free
    frame_table_entry->page = NULL;
    lock_release(&frame_table_entry->lock);
}

void frame_lock(struct frame_table_entry* frame_table_entry){
    ASSERT(frame_table_entry != NULL);
    lock_acquire(&frame_table_entry->lock);
}

void frame_unlock(struct frame_table_entry* frame_table_entry){
    ASSERT(frame_table_entry != NULL);
    ASSERT(lock_held_by_current_thread(&frame_table_entry->lock));
    lock_release(&frame_table_entry->lock);
}


static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}