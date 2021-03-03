#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H


/* Lock ensures filesystem synch. */
struct lock lock_of_filesys;

void syscall_init (void);


#endif /* userprog/syscall.h */
