#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void exit (int status);

struct lock filesys_lock;

#endif /* userprog/syscall.h */
