#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#define THREAD_MAGIC 0xcd6abf4b
typedef int pid_t;

/* Lock ensures filesystem synch. */
struct lock lock_of_filesys;

static void syscall_handler (struct intr_frame *f);
//sys calls
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

/* Helper functions */

/* Find file in given thread's opened files list by file descriptor. */
struct file_with_fd* find_file_by_fd (struct thread* t, int fd);

/* Check whether given pointer points to a valid address. */
void check_pointer (void* ptr, size_t offset);

bool check_exec (char *exec_name);

/* Remove all child processes and close all opened files in given thread. */
void release_resources_in_thread (struct thread* t);

/*Functions from doc. */
static bool put_user (uint8_t *udst, uint8_t byte);
static int get_user (const uint8_t *uaddr);

struct file_with_fd* find_file_by_fd (struct thread* t, int fd)
{
  struct file_with_fd* target = NULL;
  
  /* Invalid argument. */
  if (t == NULL || fd < 2 || fd > t->fd_num)
    return NULL;
  
  for (struct list_elem* ptr = list_begin(&t->opened_files); 
        ptr != list_end(&t->opened_files); 
        ptr = ptr->next)
    {
      target = list_entry(ptr, struct file_with_fd, elem);
      if (target->fd == fd) 
        break;
    }

  return target;
}

/* Check whether the exec_name if valid. */
bool check_exec (char *exec_name)
{
  bool flag = false;

  if (exec_name == NULL)
    return flag;

  lock_acquire(&lock_of_filesys);
  struct file* file = filesys_open(exec_name);
  flag = (file != NULL);
  file_close(file);
  lock_release(&lock_of_filesys);

  return flag;
}

/* Check whether ptr to ptr + offset is valid. */
void check_pointer(void* ptr, size_t offset)
{
  if (ptr == NULL)
    exit(-1);

  bool flag = false;
  struct thread* cur = thread_current ();
  for (int i = 0; i < offset; i++)
    {
      /* 1. NULL pointer
         2. Below kernel memory.
         3. User virtual address starts at 0x08048000.
         4. Mapped pagedir. */
      flag = ((ptr + i) != NULL)
             && is_user_vaddr(ptr + i) 
             && ((ptr + i) >= (void*) 0x08048000)
             && (pagedir_get_page(cur->pagedir, ptr + i) != NULL);
      if (!flag)
        exit(-1);
    }
}


void release_resources_in_thread (struct thread* t)
{
  
  if (t == NULL)
    return;
  
  struct child_process* child = NULL;
  struct list_elem* ptr = NULL;
  struct thread* tmp = NULL;
  struct file_with_fd* ffd = NULL;

  /* 1. Release child processes. */
  while (!list_empty(&t->child_processes))
  {
    ptr = list_pop_front(&t->child_processes);
    child = list_entry(ptr, struct child_process, elem);
    tmp = get_thread_by_tid(child->tid);
    free(child);
  }

  /* 2. Release opened files. */
  lock_acquire(&lock_of_filesys);

  /* Close file and remove it from the opened file list. */
  file_close(t->executable_file);
  while (!list_empty(&t->opened_files))
    {
      ptr = list_pop_front(&t->opened_files);
      ffd = list_entry(ptr, struct file_with_fd, elem);
      file_close(ffd->file);
      free(ffd);
    }
  t->executable_file = NULL;

  lock_release(&lock_of_filesys);

}


void
syscall_init (void) 
{
  /* Initialize the lock to ensure synch. */
  lock_init(&lock_of_filesys);

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* Check pointer first. If invalid, exit immediately. */
static void
syscall_handler (struct intr_frame *f) 
{
  
  ASSERT(f != NULL);
  int32_t syscall_number=1;

  /* f->esp saved stack pointer
     f->eax to store return value */

  check_pointer(f->esp, sizeof(int));

  syscall_number = *(int*)f->esp;
  struct thread* cur = thread_current ();
  //printf("syscall of number : %d \n", syscall_number);
  //call corresponding handler based on syscall number
  switch (syscall_number){
    case SYS_HALT:
    {
      halt();
      break;
    }
    case SYS_EXIT:
    {
      check_pointer((void*)((int*)f->esp + 1), sizeof(int));

      int status = *((int*)f->esp + 1);

      exit(status);
      break;
    }
    case SYS_EXEC:
    {
      check_pointer((void*)(((int*)f->esp + 1)), sizeof(char*));
      check_pointer((void*)(*((int*)f->esp + 1)), sizeof(char) + 2);

      char *cmd_line = (char*)(*((int*)f->esp + 1));

      pid_t ret = exec(cmd_line);
      f->eax = (uint32_t)ret;
      break;
    }
    case SYS_WAIT:
    {
      check_pointer((void*)((pid_t*)f->esp + 1), sizeof(int));

      pid_t pid = *((pid_t*)f->esp + 1);
      int ret = wait(pid);
      
      f->eax = (uint32_t)ret;
      break;
    }
    case SYS_CREATE:
    {
      check_pointer((void*)((unsigned*)f->esp + 2), sizeof(unsigned));
      check_pointer((void*)(*((int*)f->esp + 1)), sizeof(char));
      
      char *file = (char*)(*((int*)f->esp + 1));
      unsigned initial_size = *((unsigned*)f->esp + 2);
      bool ret = create(file, initial_size);
      f->eax = (uint32_t)ret;
      break;
    }
    case SYS_REMOVE:
    {
      check_pointer((void*)((int*)f->esp + 1), sizeof(char*));
      check_pointer((void*)(*((int*)f->esp + 1)), sizeof(char));

      char *file = (char*)(*((int*)f->esp + 1));
      bool ret = remove(file);
      f->eax = (uint32_t)ret;
      break;
    }
    case SYS_OPEN:
    {
      check_pointer((void*)((int*)f->esp + 1), sizeof(char*));
      check_pointer((void*)(*((int*)f->esp + 1)), sizeof(char));

      char *file = (char*)(*((int*)f->esp + 1));
      int ret = open(file);
      f->eax = (uint32_t)ret;
      break;
    }
    case SYS_FILESIZE:
    {
      check_pointer((void*)((int*)f->esp + 1), sizeof(int));
   
      int fd = *((int*)f->esp + 1);
      int ret = filesize(fd);
      f->eax = (uint32_t)ret;
      break;
    }
    case SYS_READ:
    {
      check_pointer((void*)((unsigned*)f->esp + 3), sizeof(unsigned));
      unsigned size = *((unsigned*)f->esp + 3);

      check_pointer((void*)(*((int*)f->esp + 2)), size);

      int fd = *((int*)f->esp + 1);
      void *buffer = (void*)(*((int*)f->esp + 2));
      int ret = read(fd, buffer, size);
      f->eax = (uint32_t)ret;
      break;
    }
    case SYS_WRITE:
    {
      check_pointer((void*)((unsigned*)f->esp + 3), sizeof(unsigned));
      unsigned size = *((unsigned*)f->esp + 3);

      check_pointer((void*)(*((int*)f->esp + 2)), size);

      int fd = *((int*)f->esp + 1);
      void *buffer = (void*)(*((int*)f->esp + 2));
      
      int ret = write(fd, buffer, size);
      f->eax = (uint32_t)ret;
      break;
    }
    case SYS_SEEK:
    {
      check_pointer((void*)((int*)f->esp + 2), sizeof(unsigned));

      int fd = *((int*)f->esp + 1);
      unsigned position = *((unsigned*)f->esp + 2);
      seek(fd, position);
      break;
    }
    case SYS_TELL:
    {
      check_pointer((void*)((int*)f->esp + 1), sizeof(int));

      int fd = *((int*)f->esp + 1);
      unsigned ret = tell(fd);
      f->eax = (uint32_t)ret;
      break;
    }
    case SYS_CLOSE:
    {
      check_pointer((void*)((int*)f->esp + 1), sizeof(int));
   
      int fd = *((int*)f->esp + 1);
      close(fd);
      break;
    }
    default:
      exit(-1);
      break;
  }
}

/*
System Call: void halt (void)
Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h). 
This should be seldom used, because you lose some information about possible deadlock situations, etc.*/

void halt(void){
  shutdown_power_off();
}

/*
System Call: void exit (int status)
Terminates the current user program, returning status to the kernel. 
If the process's parent waits for it (see below), this is the status that will be returned. Conventionally, a status of 0 indicates success and nonzero values indicate errors.*/

void exit(int status){

  struct thread* cur = thread_current ();
  cur->exit_status = status;
  thread_exit();
}

/*
System Call: pid_t exec (const char *cmd_line)
Runs the executable whose name is given in cmd_line, passing any given arguments, 
and returns the new process's program id (pid). Must return pid -1, 
which otherwise should not be a valid pid, if the program cannot load or run for any reason. 
Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. 
You must use appropriate synchronization to ensure this.*/

pid_t exec(const char *cmd_line){
  
  if (cmd_line == NULL)
    return -1;

  return process_execute(cmd_line);
}

/*
System Call: int wait (pid_t pid)
Waits for a child process pid and retrieves the child's exit status.
If pid is still alive, waits until it terminates. 
Then, returns the status that pid passed to exit. 
If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1. 
It is perfectly legal for a parent process to wait for child processes that have already terminated by the time the parent calls wait, 
but the kernel must still allow the parent to retrieve its child's exit status, or learn that the child was terminated by the kernel.
wait must fail and return -1 immediately if any of the following conditions is true:

pid does not refer to a direct child of the calling process. 
pid is a direct child of the calling process if and only if the calling process received pid as a return value from a successful call to exec.
Note that children are not inherited: if A spawns child B and B spawns child process C, then A cannot wait for C, 
even if B is dead. A call to wait(C) by process A must fail. Similarly, 
orphaned processes are not assigned to a new parent if their parent process exits before they do.

The process that calls wait has already called wait on pid. That is, a process may wait for any given child at most once.
Processes may spawn any number of children, wait for them in any order, 
and may even exit without having waited for some or all of their children. 
Your design should consider all the ways in which waits can occur. All of a process's resources, 
including its struct thread, must be freed whether its parent ever waits for it or not, 
and regardless of whether the child exits before or after its parent.

You must ensure that Pintos does not terminate until the initial process exits. 
The supplied Pintos code tries to do this by calling process_wait() (in userprog/process.c) from main() (in threads/init.c). 
We suggest that you implement process_wait() according to the comment at the top of the function 
and then implement the wait system call in terms of process_wait().

Implementing this system call requires considerably more work than any of the rest.*/

int wait(pid_t pid) 
{
  return process_wait(pid);
}

/*
System Call: bool create (const char *file, unsigned initial_size)
Creates a new file called file initially initial_size bytes in size. 
Returns true if successful, false otherwise. 
Creating a new file does not open it: opening the new file is a separate operation which would require a open system call.*/

bool create(const char *file, unsigned initial_size){
  bool flag = false;
  if (file != NULL)
    {
      lock_acquire(&lock_of_filesys);
      flag = filesys_create(file, initial_size);
      lock_release(&lock_of_filesys);
    }
  return flag;
}

/*
System Call: bool remove (const char *file)
Deletes the file called file. Returns true if successful, false otherwise. 
A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. 
See Removing an Open File, for details.*/

bool remove(const char *file){
  bool flag = false;
  if (file != NULL)
    {
      lock_acquire(&lock_of_filesys);
      flag = filesys_remove(file);
      lock_release(&lock_of_filesys);
    }
  return flag;
}

/*
System Call: int open (const char *file)
Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output.
The open system call will never return either of these file descriptors, 
which are valid as system call arguments only as explicitly described below.

Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.

When a single file is opened more than once, whether by a single process or different processes, 
each open returns a new file descriptor. 
Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position.*/

int open(const char *file){
  int fd = -1;
  struct file_with_fd* ffd = malloc(sizeof(*ffd));
  struct thread* cur = thread_current ();

  lock_acquire(&lock_of_filesys);
  struct file* f = filesys_open(file);

  if (f != NULL)
    {
      ffd->file = f;

      /* Allocate file descriptor. */
      ffd->fd = cur->fd_num;
      
      /* Add to opened_files list. */
      list_push_back(&cur->opened_files, &ffd->elem);

      /* Thread's fd should increase. */
      cur->fd_num++;

      /* Return value. */
      fd = ffd->fd;
    }
  else
    free(ffd);
 
  lock_release(&lock_of_filesys);
  return fd;
}

/*
System Call: int filesize (int fd)
Returns the size, in bytes, of the file open as fd.*/

int filesize(int fd){
  struct thread* cur = thread_current ();
  off_t size = -1;

  lock_acquire(&lock_of_filesys);
  struct file_with_fd* ffd = find_file_by_fd(cur, fd);

  if (ffd != NULL)
    size = file_length(ffd->file);
  
  lock_release(&lock_of_filesys);

  return size;
}

/*
System Call: int read (int fd, void *buffer, unsigned size)
Reads size bytes from the file open as fd into buffer. 
Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file). 
Fd 0 reads from the keyboard using input_getc().
*/
int read(int fd, void *buffer, unsigned size){
  int bytes = -1;
  struct thread* cur = thread_current ();
  struct file_with_fd* ffd = find_file_by_fd(cur, fd);

  if (buffer == NULL)
    return bytes;

  lock_acquire(&lock_of_filesys);
  
  /* If fd == stdin. */
  if (fd == 0)
    {
      for (int i = 0; i < size; i++)
        *((char*)buffer + i) = input_getc();

      bytes = size;
    }
  /* Read from file. */
  else if (ffd != NULL)
    {  
      bytes = file_read(ffd->file, buffer, size);
    }
  
  lock_release(&lock_of_filesys);

  return bytes;
}

/*
System Call: int write (int fd, const void *buffer, unsigned size)
Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, 
which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. 
The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, 
or 0 if no bytes could be written at all.

Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(),
 at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) 
 Otherwise, lines of text output by different processes may end up interleaved on the console, 
 confusing both human readers and our grading scripts.*/

int write(int fd, const void *buffer, unsigned size){

  int bytes = -1;
  struct thread* cur = thread_current ();
  struct file_with_fd* ffd = find_file_by_fd(cur, fd);

  if (buffer == NULL)
    return bytes;

  lock_acquire(&lock_of_filesys);
  
  /* If fd == stdout. */
  if (fd == 1)
    {
      putbuf(buffer, size);
      bytes = size;
    }
  /* Write in file. */
  else if (ffd != NULL)
    {  
      bytes = file_write(ffd->file, buffer, size);
    }
  
  lock_release(&lock_of_filesys);

  return bytes;
}

/*
System Call: void seek (int fd, unsigned position)
Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. 
(Thus, a position of 0 is the file's start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. 
A later write extends the file, filling any unwritten gap with zeros. 
(However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.)
 These semantics are implemented in the file system and do not require any special effort in system call implementation.*/

void seek (int fd, unsigned position){
  struct thread* cur = thread_current ();
  struct file_with_fd* ffd = find_file_by_fd(cur, fd);

  lock_acquire(&lock_of_filesys);
  
  if (ffd != NULL)
    {  
      file_seek(ffd->file, position);
    }
  
  lock_release(&lock_of_filesys);
}

/*
System Call: unsigned tell (int fd)
Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.*/

unsigned tell (int fd){
  struct thread* cur = thread_current ();
  struct file_with_fd* ffd = find_file_by_fd(cur, fd);
  int ret = -1;

  lock_acquire(&lock_of_filesys);
  
  if (ffd != NULL)
    {  
      ret = file_tell(ffd->file);
    }
  
  lock_release(&lock_of_filesys);
  return ret;
}

/*
System Call: void close (int fd)
Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, 
as if by calling this function for each one.
*/

void close (int fd){
  struct thread* cur = thread_current ();
  struct file_with_fd* ffd = find_file_by_fd(cur, fd);

  lock_acquire(&lock_of_filesys);
  
  if (ffd != NULL)
  {  
    /* Remove from list and close file. */
    list_remove(&ffd->elem);
    file_close(ffd->file);

    /* Free allocated space. */
    free(ffd);
  }
  
  lock_release(&lock_of_filesys);
}


// Memory Access Functions

// Copy from document

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}




