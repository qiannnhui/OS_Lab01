// #include "userprog/syscall.h"
// #include <stdio.h>
// #include <syscall-nr.h>
// #include "threads/interrupt.h"
// #include "threads/thread.h"

// #include <devices/shutdown.h>

// #include <string.h>
// #include <filesys/file.h>
// #include <devices/input.h>
// #include <threads/malloc.h>
// #include <threads/palloc.h>
// #include "process.h"
// #include "pagedir.h"
// #include <threads/vaddr.h>
// #include <filesys/filesys.h>

// #define MAX_SYSCALL 20

// // lab01 Hint - Here are the system calls you need to implement.

// /* System call for process. */

// void sys_halt(void);
// void sys_exit(struct intr_frame* f);
// void sys_exec(struct intr_frame* f);
// void sys_wait(struct intr_frame* f);

// /* System call for file. */
// void sys_create(struct intr_frame* f);
// void sys_remove(struct intr_frame* f);
// void sys_open(struct intr_frame* f);
// void sys_filesize(struct intr_frame* f);
// void sys_read(struct intr_frame* f);
// void sys_write(struct intr_frame* f);
// void sys_seek(struct intr_frame* f);
// void sys_tell(struct intr_frame* f);
// void sys_close(struct intr_frame* f);

// void * is_valid_addr(const void *vaddr)
// {
// 	void *page_ptr = NULL;
// 	if (!is_user_vaddr(vaddr) || !(page_ptr = pagedir_get_page(thread_current()->pagedir, vaddr)))
// 	{
// 		exit_process(-1);
// 		return 0;
// 	}
// 	return page_ptr;
// }
// void pop_stack(int *esp, int *a, int offset){
// 	int *tmp_esp = esp;
// 	*a = *((int *)is_valid_addr(tmp_esp + offset));
// }


// void exit_process(int status)
// {
// 	// struct child_process *cp;
// 	// struct thread *cur_thread = thread_current();

// 	// enum intr_level old_level = intr_disable();
// 	// struct list_elem *e;
// 	// for (e = list_begin(&cur_thread->parent->children_list); e != list_end(&cur_thread->parent->children_list); e = list_next(e)) {
// 	// 	cp = list_entry(e, struct child_process, child_elem);
// 	// 	if (cp->tid == cur_thread->tid)
// 	// 	{
// 	// 		cp->if_waited = true;
// 	// 		cp->exit_status = status;
// 	// 	}
// 	// }
// 	// cur_thread->exit_status = status;
// 	// intr_set_level(old_level);
// 	struct thread *cur = thread_current();
// 	if (cur->child_elem != NULL)
//     cur->child_elem->exit_status = status;	printf ("%s: exit(%d)\n", cur->name, status);

// 	thread_exit();
// }


// static void (*syscalls[MAX_SYSCALL])(struct intr_frame *) = {
//   [SYS_HALT] = sys_halt,
//   [SYS_EXIT] = sys_exit,
//   [SYS_EXEC] = sys_exec,
//   [SYS_WAIT] = sys_wait,
//   [SYS_CREATE] = sys_create,
//   [SYS_REMOVE] = sys_remove,
//   [SYS_OPEN] = sys_open,
//   [SYS_FILESIZE] = sys_filesize,
//   [SYS_READ] = sys_read,
//   [SYS_WRITE] = sys_write,
//   [SYS_SEEK] = sys_seek,
//   [SYS_TELL] = sys_tell,
//   [SYS_CLOSE] = sys_close
// };

// static void syscall_handler (struct intr_frame *);

// void syscall_init (void) 
// {
// 	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
// }


// /* System Call: void halt (void)
//     Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h). 
// */
// void sys_halt(void)
// {
// 	shutdown_power_off();
// }


// void
// sys_exit(struct intr_frame *f)
// {
// 	printf("exit\n");
// 	int status;
// 	pop_stack(f->esp, &status, 1);
// 	exit_process(status);
// }

// void sys_exec(struct intr_frame *f)
// {
// 	printf("exec\n");
// 	// int ret;
// 	// char *cmd_line;
// 	// pop_stack(f->esp, &cmd_line, 2);
// 	// if (!is_valid_addr(cmd_line))
// 	// 	ret = -1;
// 	// else
// 	// {
// 	// 	ret = process_execute(cmd_line);
// 	// }
// 	// return ret;
// }

// void sys_wait(struct intr_frame *f)
// {
// 	printf("wait\n");
// 	// int ret;
// 	// int pid;
// 	// pop_stack(f->esp, &pid, 3);
// 	// if (pid < 0)
// 	// 	ret = -1;
// 	// else
// 	// {
// 	// 	ret = process_wait(pid);
// 	// }
// 	// return ret;
// }

// void sys_create(struct intr_frame *f)
// {
// 	printf("create\n");
// 	// int ret;
// 	// int size;
// 	// char *file_name;
// 	// pop_stack(f->esp, &size, 4);
// 	// pop_stack(f->esp, &file_name, 3);
// 	// if (!is_valid_addr(file_name))
// 	// 	ret = -1;
// 	// else
// 	// {
// 	// 	ret = filesys_create(file_name, size);
// 	// }
// 	// return ret;
// }

// void sys_remove(struct intr_frame *f)
// {
// 	printf("remove\n");
// 	// int ret;
// 	// char *file_name;
// 	// pop_stack(f->esp, &file_name, 4);
// 	// if (!is_valid_addr(file_name))
// 	// 	ret = -1;
// 	// else
// 	// {
// 	// 	ret = filesys_remove(file_name);
// 	// }
// 	// return ret;
// }

// void sys_open(struct intr_frame *f)
// {
// 	printf("open\n");
// 	// int ret;
// 	// char *file_name;
// 	// pop_stack(f->esp, &file_name, 3);
// 	// if (!is_valid_addr(file_name))
// 	// 	ret = -1;
// 	// else
// 	// {
// 	// 	ret = filesys_open(file_name);
// 	// }
// 	// return ret;
// }

// void sys_filesize(struct intr_frame *f)
// {
// 	printf("filesize\n");
// 	// int ret;
// 	// int fd;
// 	// pop_stack(f->esp, &fd, 2);
// 	// if (fd < 0)
// 	// 	ret = -1;
// 	// else
// 	// {
// 	// 	ret = file_length(fd);
// 	// }
// 	// return ret;
// }

// void sys_seek(struct intr_frame *f)
// {
// 	printf("seek\n");
// 	// int ret;
// 	// int fd;
// 	// int pos;
// 	// pop_stack(f->esp, &pos, 4);
// 	// pop_stack(f->esp, &fd, 3);
// 	// if (fd < 0)
// 	// 	ret = -1;
// 	// else
// 	// {
// 	// 	ret = file_seek(fd, pos);
// 	// }
// 	// return ret;
// }

// void sys_tell(struct intr_frame *f)
// {
// 	printf("tell\n");
// 	// int ret;
// 	// int fd;
// 	// pop_stack(f->esp, &fd, 2);
// 	// if (fd < 0)
// 	// 	ret = -1;
// 	// else
// 	// {
// 	// 	ret = file_tell(fd);
// 	// }
// 	// return ret;
// }

// void sys_close(struct intr_frame *f)
// {
// 	printf("close\n");
// 	// int ret;
// 	// int fd;
// 	// pop_stack(f->esp, &fd, 2);
// 	// if (fd < 0)
// 	// 	ret = -1;
// 	// else
// 	// {
// 	// 	ret = file_close(fd);
// 	// }
// 	// return ret;
// }

// void sys_read(struct intr_frame *f)
// {
// 	printf("read\n");
// }

// void sys_write(struct intr_frame *f)
// {
// 	printf("write\n");
// 	int ret;
// 	int size;
// 	void *buffer;
// 	int fd;

// 	pop_stack(f->esp, &size, 7);
// 	pop_stack(f->esp, &buffer, 6);
// 	pop_stack(f->esp, &fd, 5);

// 	if (!is_valid_addr(buffer))
// 		ret = -1;

// 	if (fd == 1)
// 	{
// 		putbuf(buffer, size);
// 		ret = size;
// 	}
// 	// else
// 	// {
// 	// 	enum intr_level old_level = intr_disable();
// 	// 	struct process_file *pf = search_fd(&thread_current()->opened_files, fd);
//   //   struct file *file = pf->ptr;
//   //   {
//   //     /* data */
//   //   };
    
// 	// 	intr_set_level (old_level);

// 	// 	if (pf == NULL)
// 	// 		ret = -1;
// 	// 	else
// 	// 	{
// 	// 		// lock_acquire(&filesys_lock);
// 	// 		ret = file_write(pf->ptr, buffer, size);
// 	// 		// lock_release(&filesys_lock);
// 	// 	}
// 	// }

// 	return ret;
// }


// static void syscall_handler (struct intr_frame *f UNUSED) 
// {
//   	printf ("system call!\n");
//     // esp: pointer of the next-command, so syscall_number is the current command
// 	// get and check syscall_number
// 	int syscall_number = * (int *)f->esp;
// 	printf("syscall_number: %d\n", syscall_number);
// 	if(syscall_number <= 0 || syscall_number >= MAX_SYSCALL){
// 		printf("syscall_number error\n");
// 		thread_exit();
// 	}
// 	// operate syscall
// 	syscalls[syscall_number](f);
// 	// int status;
// 	// pop_stack(f->esp, &status, 1);
// 	// exit_process(status);
// 	thread_exit();
// }



#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"
#include <threads/vaddr.h>
#include <filesys/filesys.h>
#include <devices/shutdown.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
# define max_syscall 20
# define USER_VADDR_BOUND (void*) 0x08048000
struct thread_file * find_file_id(int fd);
/* Our implementation for storing the array of system calls for Task2 and Task3 */
static void (*syscalls[max_syscall])(struct intr_frame *);
static void * check_ptr2(const void *vaddr);
static void exit_special (void);
struct thread_file * find_file_id(int fd);
/* Our implementation for Task2: syscall halt,exec,wait and practice */
void sys_halt(struct intr_frame* f); /* syscall halt. */
void sys_exit(struct intr_frame* f); /* syscall exit. */
void sys_exec(struct intr_frame* f); /* syscall exec. */

/* Our implementation for Task3: syscall create, remove, open, filesize, read, write, seek, tell, and close */
void sys_create(struct intr_frame* f); /* syscall create */
void sys_remove(struct intr_frame* f); /* syscall remove */
void sys_open(struct intr_frame* f);/* syscall open */
void sys_wait(struct intr_frame* f); /*syscall wait */
void sys_filesize(struct intr_frame* f);/* syscall filesize */
void sys_read(struct intr_frame* f);  /* syscall read */
void sys_write(struct intr_frame* f); /* syscall write */
void sys_seek(struct intr_frame* f); /* syscall seek */
void sys_tell(struct intr_frame* f); /* syscall tell */
void sys_close(struct intr_frame* f); /* syscall close */

static void syscall_handler (struct intr_frame *);
/* New method to check the address and pages to pass test sc-bad-boundary2, execute */
/* Handle the special situation for thread */

void 
exit_special (void)
{
  thread_current()->st_exit = -1;
  thread_exit ();
}

/* Method in document to handle special situation */
/* 在用户虚拟地址 UADDR 读取一个字节。
   UADDR 必须低于 PHYS_BASE。
   如果成功则返回字节值，如果
   发生段错误则返回 -1 。*/ 
static int 
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

void * 
check_ptr2(const void *vaddr)
{ 
  /* Judge address */
  if (!is_user_vaddr(vaddr))//是否为用户地址
  {
    exit_special ();
  }
  /* Judge the page */
  void *ptr = pagedir_get_page (thread_current()->pagedir, vaddr);//是否为用户地址
  if (!ptr)
  {
    exit_special ();
  }
  /* Judge the content of page */
  uint8_t *check_byteptr = (uint8_t *) vaddr;
  for (uint8_t i = 0; i < 4; i++) 
  {
    if (get_user(check_byteptr + i) == -1)
    {
      exit_special ();
    }
  }

  return ptr;
}




void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    /* Our implementation for Task2: initialize halt,exit,exec */
//   syscalls[SYS_EXEC] = &sys_exec;
  syscalls[SYS_HALT] = &sys_halt;
  syscalls[SYS_EXIT] = &sys_exit;
 
  // /* Our implementation for Task3: initialize create, remove, open, filesize, read, write, seek, tell, and close */
//   syscalls[SYS_WAIT] = &sys_wait;
//   syscalls[SYS_CREATE] = &sys_create;
//   syscalls[SYS_REMOVE] = &sys_remove;
//   syscalls[SYS_OPEN] = &sys_open;
  syscalls[SYS_WRITE] = &sys_write;
//   syscalls[SYS_SEEK] = &sys_seek;
//   syscalls[SYS_TELL] = &sys_tell;
//   syscalls[SYS_CLOSE] =&sys_close;
//   syscalls[SYS_READ] = &sys_read;
//   syscalls[SYS_FILESIZE] = &sys_filesize;
}

/* Smplify the code to maintain the code more efficiently */
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* For Task2 practice, just add 1 to its first argument, and print its result */
  int * p = f->esp;
  check_ptr2 (p + 1);//检验第一个参数
  int type = * (int *)f->esp;//检验系统调用号sys_code是否合法
  if(type <= 0 || type >= max_syscall){
    exit_special ();
  }
  syscalls[type](f);//无误则执行对应系统调用函数
}

/* Our implementation for Task2: halt,exit,exec */
/* Do sytem halt */
void 
sys_halt (struct intr_frame* f)
{
  shutdown_power_off();
}

/* Do sytem exit */
void 
sys_exit (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 1);//检验第一个参数
  *user_ptr++;//指针指向第一个参数
  /* record the exit status of the process */
  thread_current()->st_exit = *user_ptr;//保存exit_code
  thread_exit ();
}

/* Do system write, Do writing in stdout and write in files */
void 
sys_write (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  check_ptr2 (user_ptr + 7);//for tests maybe?
  check_ptr2 (*(user_ptr + 6));
  *user_ptr++;
  int fd = *user_ptr;
  const char * buffer = (const char *)*(user_ptr+1);
  off_t size = *(user_ptr+2);
  if (fd == 1) {//writes to the console
    /* Use putbuf to do testing */
    putbuf(buffer,size);
    f->eax = size;//return number written
  }
  else
  {
    /* Write to Files */
    struct thread_file * thread_file_temp = find_file_id (*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f ();//file operating needs lock
      f->eax = file_write (thread_file_temp->file, buffer, size);
      release_lock_f ();
    } 
    else
    {
      f->eax = 0;//can't write,return 0
    }
  }
}

/* Find file by the file's ID */
struct thread_file * 
find_file_id (int file_id)
{
  struct list_elem *e;
  struct thread_file * thread_file_temp = NULL;
  struct list *files = &thread_current ()->files;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    thread_file_temp = list_entry (e, struct thread_file, file_elem);
    if (file_id == thread_file_temp->fd)
      return thread_file_temp;
  }
  return false;
}


/* Check is the user pointer is valid */
bool 
is_valid_pointer (void* esp,uint8_t argc){
  for (uint8_t i = 0; i < argc; ++i)
  {
    if((!is_user_vaddr (esp)) || 
      (pagedir_get_page (thread_current()->pagedir, esp)==NULL)){
      return false;
    }
  }
  return true;
}