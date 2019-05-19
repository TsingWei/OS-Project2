#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#define STDOUT_FILENO 1 // 标准输出
#define STDIN_FILENO 0  // 标准输入
#define STDERR_FILENO 2 // 标准错误

void get_arg (struct intr_frame *f, int *arg, int n);
void check_valid_string (const void* str);

// 链表elem存放在thread结构体下
struct proc_file {
	struct file* ptr;
	int fd;
	struct list_elem elem;
};
struct lock file_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  
  int *esp = check_addr(f->esp);
  int arg[4];

    
  // printf("++++++++FUCK1!++++++++\n");
  int system_call = *esp;
  // printf("++++++++FUCK2!++++++++\n");
  switch (system_call)
  {
    case SYS_HALT:
      shutdown_power_off();
      break;

    case SYS_EXIT:
    {
      get_arg(f, &arg[0], 1);
      int exit_error = arg[0];
      thread_current()->parent->wait_exec = true;
      thread_current()->exit_error = exit_error;
      thread_exit();
      break;
    }

    case SYS_EXEC:
    {
      get_arg(f, &arg[0], 1);
      char* cmd_line = (char*)arg[0];
      f->eax = process_execute(cmd_line);
      break;
    }

		case SYS_WAIT:
    {
      get_arg(f, &arg[0], 1);
      int pid = arg[0];
	    f->eax =process_wait(pid);
	    break;
    }

    case SYS_CREATE:
    {
      get_arg(f, &arg[0], 2);
      check_valid_string((const void *) arg[0]);
      char* file = (char*)check_addr((const void *) arg[0]);
      unsigned initial_size = arg[1];
      lock_acquire(&file_lock);
      bool success = filesys_create(file, initial_size);
      lock_release(&file_lock);
      f->eax = success;
      break;
    }

    case SYS_REMOVE:
    {
      get_arg(f, &arg[0], 1);
      check_valid_string((const void *) arg[0]);
      char* file = (char*)check_addr((const void *) arg[0]);
      lock_acquire(&file_lock);
      bool success = filesys_remove(file);
      lock_release(&file_lock);
      f->eax = success;
	    break;
    }

    case SYS_OPEN:
    {
      get_arg(f, &arg[0], 1);
      check_valid_string((const void *) arg[0]);
      char* file = (char*)check_addr((const void *) arg[0]);
      // printf("+++++++FILENAME: %s+++++++\n",file);
      lock_acquire(&file_lock);
      struct file *_f = filesys_open(file);
      // printf("+++++++FILESIZE: %d+++++++\n",file_length(_f));
      if (!_f)
        {
          lock_release(&file_lock);
          f->eax = -1;
          break;
        }
      struct proc_file *pf = malloc(sizeof(struct proc_file));
      pf->ptr = _f;
      pf->fd = thread_current()->fd_count;
      thread_current()->fd_count++;
      list_push_back(&thread_current()->files, &pf->elem);
      lock_release(&file_lock);
      // printf("+++++++FILESIZE: %d+++++++\n",file_length(_f));
      f->eax = pf->fd;
	    break;
    }

    case SYS_FILESIZE:
    {
      get_arg(f, &arg[0], 1);
      int fd = arg[0];
      lock_acquire(&file_lock);
      struct file *_f = process_get_file(fd);
      if (!_f)
        {
          lock_release(&file_lock);
          f->eax = -1;
          break;
        }
      int size = file_length(_f);
      lock_release(&file_lock);
      f->eax = size;
	    break;
    }

    case SYS_READ:
    {
      get_arg(f, &arg[0], 3);
      int fd = arg[0];
      void *buffer =  arg[1];
      unsigned size = arg[2];
      if (fd == STDIN_FILENO)
      {
        unsigned i;
        uint8_t* local_buffer = (uint8_t *) buffer;
        for (i = 0; i < size; i++)
        {
          local_buffer[i] = input_getc();
        }
        f->eax = size;
        break;
      }
      lock_acquire(&file_lock);
      struct file *_f = process_get_file(fd);
      if (!_f)
      {
        lock_release(&file_lock);
        f->eax = -1;
        break;
      }
      int bytes = file_read(_f, buffer, size);
      lock_release(&file_lock);
      f->eax = bytes;
	    break;
    }

    case SYS_WRITE:
    {
      get_arg(f, &arg[0], 3);
      int fd = arg[0];
      void *buffer =  arg[1];
      unsigned size = arg[2];
      if (fd == STDOUT_FILENO)
      {
        putbuf(buffer, size);
        f->eax=0;
        break;
      }
      lock_acquire(&file_lock);
      struct file *_f = process_get_file(fd);
      if (!_f)
      {
        lock_release(&file_lock);
        return -1;
      }
      int bytes = file_write(_f, buffer, size);
      lock_release(&file_lock);
      f->eax = bytes;
	    break;
    }

    case SYS_SEEK:
    {
      get_arg(f, &arg[0], 1);
      int fd = arg[0];
      unsigned position = *((unsigned*)esp + 2);  
      lock_acquire(&file_lock);
      struct file *_f = process_get_file(fd);
      if (!_f)
        {
          lock_release(&file_lock);
          return;
        }
      file_seek(_f, position);
      lock_release(&file_lock);
      break;
    }

    case SYS_CLOSE:
    {
      get_arg(f, &arg[0], 1);
      int fd = arg[0];
      lock_acquire(&file_lock);
      struct thread *t = thread_current();
      struct list_elem *next, *e = list_begin(&t->files);

      while (e != list_end (&t->files))
      {
        next = list_next(e);
        struct proc_file *pf = list_entry (e, struct proc_file, elem);
        if (fd == pf->fd || fd == -1)
        {
          file_close(pf->ptr);
          list_remove(&pf->elem);
          free(pf);
          if (fd != -1)
          {
            break;
          }
        }
        e = next;
      }
      lock_release(&file_lock);  
      break;  
    }

    case SYS_TELL:
    {
      get_arg(f, &arg[0], 1);
      int fd = arg[0];
      lock_acquire(&file_lock);
      struct file *_f = process_get_file(fd);
      if (!_f)
        {
          lock_release(&file_lock);
          f->eax = -1;
          break;
        }
      off_t offset = file_tell(_f);
      lock_release(&file_lock);
      f->eax = offset;  
      break;  
    }

    default:
    {
      thread_current()->parent->wait_exec = true;
      thread_current()->exit_error = -1;
      thread_exit();
      break;
    }			
      
		}

  
}
// 从当前线程所打开的文件中找到FD对应的file指针
struct file* process_get_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;
    for (e = list_begin (&t->files); e != list_end (&t->files);
        e = list_next (e))
    {
      struct proc_file *file = list_entry (e, struct proc_file, elem);
      if(file->fd == fd){
        // printf("+++++++FILESIZE: %d+++++++\n",file_length(file));
        return file->ptr;
      }
        
    }
   return NULL;
}

// 关闭当前进程所有打开的的文件
void process_close_file( int fd)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->files);

  while (e != list_end (&t->files))
  {
    next = list_next(e);
    struct proc_file *pf = list_entry (e, struct proc_file, elem);
    if (fd == pf->fd || fd == -1)
    {
      file_close(pf->ptr);
      list_remove(&pf->elem);
      free(pf);
      if (fd != -1)
      {
        break;
      }
    }
    e = next;
  }
}

// 检查地址是否为用户空间地址,并检查对应page是否存在,并且返回对应的内核可见地址
void* check_addr(const void *vaddr)
{
	if (!is_user_vaddr(vaddr))
	{
		thread_current()->parent->wait_exec = true;
		thread_current()->exit_error = -1;
		thread_exit();
		return 0;
	}
	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	if (!ptr)
	{
		thread_current()->parent->wait_exec = true;
		thread_current()->exit_error = -1;
		thread_exit();
		return 0;
	}
	return (int)ptr;
}

// 从esp起得到参数,同时检查参数指针合法性. 参数不会超过4个
void get_arg (struct intr_frame *f, int *arg, int n)
{
  int i;
  int *ptr;
  for (i = 0; i < n; i++)
    {
      ptr = (int *) f->esp + i + 1;
      check_addr((const void *) ptr);
      arg[i] = *ptr;
    }
}

// 检查一个字符串是否合法(不为空, 所有字符地址都合法)
void check_valid_string (const void* str)
{
  while (* (char *) check_addr(str) != 0)
    {
      str = (char *) str + 1;
    }
}

