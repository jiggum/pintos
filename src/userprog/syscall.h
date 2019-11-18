#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void syscall_exit (int status);

void syscall_lock_acquire (void);
void syscall_lock_release (void);

#endif /* userprog/syscall.h */
