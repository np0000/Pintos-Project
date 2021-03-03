#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define THREAD_MAGIC 0xcd6abf4b
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
struct child_process* get_child_process(struct thread* t, tid_t child_tid);



/* Get child_process in parent process by tid. */
struct child_process* get_child_process(struct thread* t, tid_t child_tid)
{
  if (list_empty(&t->child_processes))
    return NULL;

  struct child_process* target = NULL;

  enum intr_level old_level = intr_disable();

  for (struct list_elem* ptr = list_begin(&t->child_processes); 
  ptr != list_end(&t->child_processes); ptr = ptr->next)
    {
      struct child_process* tmp = list_entry(ptr, struct child_process, elem);
      if (tmp->tid == child_tid) 
        {
          target = tmp;
          break;
        }
    }
  intr_set_level (old_level);
  return target;
}


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  struct thread* parent = thread_current ();

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* change file name to exec name
     need to malloc space as pointer should be passed in. */
  char *exec_name = malloc(strlen(file_name) + 1);
  if (exec_name == NULL)
    return TID_ERROR;
  strlcpy(exec_name, file_name, strlen(file_name) + 1);
  //contain the string left over
  char *leftover;
  exec_name = strtok_r(exec_name, " ", &leftover);

  if (!check_exec (exec_name))
    return TID_ERROR;  

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (exec_name, PRI_DEFAULT, start_process, fn_copy);

  //free space malloced
  free (exec_name);

  /* Should wait until child process finishes load. */
  sema_down (&parent->load_sema);

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
    
  /* If load failed, should return -1. */
  if (!parent->child_load_status)
    tid = TID_ERROR;

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  struct thread* parent = thread_current ()->parent;
  struct thread* cur = thread_current ();

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  palloc_free_page (file_name);
  
  /* Let parent know whether child process successfully loaded. */
  parent->child_load_status = success;

  /* Tell parent that load finished. */
  sema_up(&parent->load_sema);
  
  if (!success) 
    {
      /* If load failed but added to parent's child_processes, remove. */
      struct child_process* child = get_child_process(parent, cur->tid);

      /* We shouldn't have pushed back child in parent's child_processes if 
         loaded failed but we did. So remove it here. */
      if (child != NULL)
        {
          list_remove(&child->elem);
          free(child);
        }

      /* Load failed. Exit status should be -1 and thread exit. */
      exit(-1);
    }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  int return_value = -1;

  /* If TID is invalid. */
  if (child_tid < 1) 
    return return_value;

  struct thread* parent = thread_current ();
  
  /* Get child_process by given tid. */
  struct child_process* child = get_child_process (parent, child_tid);
  
  /* It was not a child of the calling process, 
     or if process_wait() has already been successfully called for the given TID. */
  if (child == NULL || child->waited)
    return return_value;
  
  /* Init return value. */
  return_value = child->child_exit_status;
  child->waited = true;

  /* Check whether child has already exit. */
  if (return_value == INITIAL_STATUS)
    {
      /* Let parent which child it is waiting for. */
      parent->waited_child = child_tid;

      /* Wait until child exits. Use semaphore to synch. */
      sema_down(&child->wait_sema);
      
      /* Parent now isn't waiting for any child. */
      parent->waited_child = INITIAL_STATUS;

      /* Return child's exit status. */
      return_value = child->child_exit_status;
    }

  return return_value;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  struct thread* parent = cur->parent;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  
  if (pd != NULL) 
    {
      if (parent != NULL) 
        {
          /* Change child's info in parent's child processes list. */
          struct child_process* child = get_child_process(parent, cur->tid);
          
          /* If child isn't NULL, it means this process is loaded successfully. */
          if (child != NULL)
            {
              /* Let parent know cur thread's exit_status. */
              child->child_exit_status = cur->exit_status;

              /* If cur is parent waiting thread, we should sema_up the semaphore.
                  Let parent know child finished. */
              if (parent->waited_child == cur->tid) 
                sema_up (&child->wait_sema);
            }

        }
      
      release_resources_in_thread (cur);

      /* Display required info. */
      printf("%s: exit(%d)\n", cur->name, cur->exit_status);

      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  //change raw file name to exec file name
  //need to malloc space as pointer should be passed in
  char *exec_name = malloc(strlen(file_name) + 1);
  strlcpy(exec_name, file_name, strlen(file_name) + 1);
  //contain the string left over
  char *leftover;
  exec_name = strtok_r(exec_name, " ", &leftover);
  /* Open executable file. */
  file = filesys_open (exec_name);

  //free space malloced
  free(exec_name);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Don't let other process change current process's executable
     file. */
  file_deny_write(file);
  t->executable_file = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);
  if (!success && file != NULL)
    {
      t->executable_file = NULL;
      file_close (file);
    }
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
// raw file name is passed in
static bool
setup_stack (void **esp, char *file_name) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }


  //copy file name for editing
  char *fn_copy = malloc(strlen(file_name) + 1);
  strlcpy(fn_copy, file_name, strlen(file_name) + 1);

  //set an array of char *, to save pointers to arguments
  int max_arg_num = 129;
  int arg_num = 0;
  int esp_saver[max_arg_num];
  char *arg_saver[max_arg_num];

  //parse all arguments
  char *token, *save_ptr;
  for (token = strtok_r (fn_copy, " ", &save_ptr); token != NULL;
      token = strtok_r (NULL, " ", &save_ptr)){
    
    arg_saver[arg_num] = token;
    
    //count number of arguments
    arg_num ++;
    if (arg_num >= max_arg_num - 1){
      printf("too many arguments in setup_stack\n");
      break;
    }

  }

  //push arguments to stack
  for (int i = arg_num - 1; i >= 0; i--){
    *esp -= strlen(arg_saver[i]) + 1;
    memcpy(*esp, arg_saver[i], strlen(arg_saver[i]) + 1);
    esp_saver[i] = *esp;
  }

  //keep memory aligned to 4 bytes
  int word_align = (int)(*esp) % 4;
  if (word_align < 0){
    word_align += 4;
  }
  *esp -= word_align;
  memset(*esp, 0, word_align);

  //4 bytes of 0
  *esp -= 4;
  esp_saver[arg_num] = *esp;
  memset(*esp, 0, 4);

  //push pointers to stack
  for (int i = arg_num - 1; i >= 0; i--){
    *esp -= sizeof(char*);
    memcpy(*esp, &esp_saver[i], sizeof(char*));
  }
  

  //write the address of argv[0]
  int last_esp = *esp;
  *esp -= sizeof(int);
  memcpy(*esp, &last_esp, sizeof(int));

  //write the number of args
  *esp -= 4;
  memcpy(*esp, &arg_num, sizeof(int));

  //write return address 0
  *esp -= 4;
  memset(*esp, 0, 4);

  //free space taken
  free(fn_copy);

  //display stack values
  //hex_dump(*esp, *esp, PHYS_BASE - *esp, true);

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
