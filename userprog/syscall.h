#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void* check_addr(const void *vaddr);
void process_close_file( int fd);
struct file* process_get_file (int fd);

#endif /* userprog/syscall.h */
