#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
void syscall_init (void);
void* check_addr(const void *vaddr);
void process_close_file( int fd);
struct file* process_get_file (int fd);
void exit_proc(int status);
int exec_proc(char *file_name);
struct child_process* get_child_process (int tid);
struct child_process {
    int tid;
    struct list_elem elem;
    int exit_error;
    bool used; // 每个子进程只能唤醒wait一次
};
#endif /* userprog/syscall.h */
