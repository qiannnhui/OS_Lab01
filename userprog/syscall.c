#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include <devices/shutdown.h>

#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
#include "process.h"
#include "pagedir.h"
#include <threads/vaddr.h>
#include <filesys/filesys.h>

#define MAX_SYSCALL 20

// lab01 Hint - Here are the system calls you need to implement.

/* System call for process. */

void sys_halt(void);
void sys_exit(struct intr_frame* f);
void sys_exec(struct intr_frame* f);
void sys_wait(struct intr_frame* f);

/* System call for file. */
void sys_create(struct intr_frame* f);
void sys_remove(struct intr_frame* f);
void sys_open(struct intr_frame* f);
void sys_filesize(struct intr_frame* f);
void sys_read(struct intr_frame* f);
void sys_write(struct intr_frame* f);
void sys_seek(struct intr_frame* f);
void sys_tell(struct intr_frame* f);
void sys_close(struct intr_frame* f);

void * is_valid_addr(const void *vaddr)
{
	void *page_ptr = NULL;
	if (!is_user_vaddr(vaddr) || !(page_ptr = pagedir_get_page(thread_current()->pagedir, vaddr)))
	{
		exit_process(-1);
		return 0;
	}
	return page_ptr;
}
void pop_stack(int *esp, int *a, int offset){
	int *tmp_esp = esp;
	*a = *((int *)is_valid_addr(tmp_esp + offset));
}


void exit_process(int status)
{
	// struct child_process *cp;
	// struct thread *cur_thread = thread_current();

	// enum intr_level old_level = intr_disable();
	// struct list_elem *e;
	// for (e = list_begin(&cur_thread->parent->children_list); e != list_end(&cur_thread->parent->children_list); e = list_next(e)) {
	// 	cp = list_entry(e, struct child_process, child_elem);
	// 	if (cp->tid == cur_thread->tid)
	// 	{
	// 		cp->if_waited = true;
	// 		cp->exit_status = status;
	// 	}
	// }
	// cur_thread->exit_status = status;
	// intr_set_level(old_level);

	thread_exit();
}


static void (*syscalls[MAX_SYSCALL])(struct intr_frame *) = {
  [SYS_HALT] = sys_halt,
  [SYS_EXIT] = sys_exit,
  [SYS_EXEC] = sys_exec,
  [SYS_WAIT] = sys_wait,
  [SYS_CREATE] = sys_create,
  [SYS_REMOVE] = sys_remove,
  [SYS_OPEN] = sys_open,
  [SYS_FILESIZE] = sys_filesize,
  [SYS_READ] = sys_read,
  [SYS_WRITE] = sys_write,
  [SYS_SEEK] = sys_seek,
  [SYS_TELL] = sys_tell,
  [SYS_CLOSE] = sys_close
};

static void syscall_handler (struct intr_frame *);

void syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* System Call: void halt (void)
    Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h). 
*/
void sys_halt(void)
{
	shutdown_power_off();
}


void
sys_exit(struct intr_frame *f)
{
	printf("exit\n");
	int status;
	pop_stack(f->esp, &status, 1);
	exit_process(status);
}

void sys_exec(struct intr_frame *f)
{
	printf("exec\n");
	// int ret;
	// char *cmd_line;
	// pop_stack(f->esp, &cmd_line, 2);
	// if (!is_valid_addr(cmd_line))
	// 	ret = -1;
	// else
	// {
	// 	ret = process_execute(cmd_line);
	// }
	// return ret;
}

void sys_wait(struct intr_frame *f)
{
	printf("wait\n");
	// int ret;
	// int pid;
	// pop_stack(f->esp, &pid, 3);
	// if (pid < 0)
	// 	ret = -1;
	// else
	// {
	// 	ret = process_wait(pid);
	// }
	// return ret;
}

void sys_create(struct intr_frame *f)
{
	printf("create\n");
	// int ret;
	// int size;
	// char *file_name;
	// pop_stack(f->esp, &size, 4);
	// pop_stack(f->esp, &file_name, 3);
	// if (!is_valid_addr(file_name))
	// 	ret = -1;
	// else
	// {
	// 	ret = filesys_create(file_name, size);
	// }
	// return ret;
}

void sys_remove(struct intr_frame *f)
{
	printf("remove\n");
	// int ret;
	// char *file_name;
	// pop_stack(f->esp, &file_name, 4);
	// if (!is_valid_addr(file_name))
	// 	ret = -1;
	// else
	// {
	// 	ret = filesys_remove(file_name);
	// }
	// return ret;
}

void sys_open(struct intr_frame *f)
{
	printf("open\n");
	// int ret;
	// char *file_name;
	// pop_stack(f->esp, &file_name, 3);
	// if (!is_valid_addr(file_name))
	// 	ret = -1;
	// else
	// {
	// 	ret = filesys_open(file_name);
	// }
	// return ret;
}

void sys_filesize(struct intr_frame *f)
{
	printf("filesize\n");
	// int ret;
	// int fd;
	// pop_stack(f->esp, &fd, 2);
	// if (fd < 0)
	// 	ret = -1;
	// else
	// {
	// 	ret = file_length(fd);
	// }
	// return ret;
}

void sys_seek(struct intr_frame *f)
{
	printf("seek\n");
	// int ret;
	// int fd;
	// int pos;
	// pop_stack(f->esp, &pos, 4);
	// pop_stack(f->esp, &fd, 3);
	// if (fd < 0)
	// 	ret = -1;
	// else
	// {
	// 	ret = file_seek(fd, pos);
	// }
	// return ret;
}

void sys_tell(struct intr_frame *f)
{
	printf("tell\n");
	// int ret;
	// int fd;
	// pop_stack(f->esp, &fd, 2);
	// if (fd < 0)
	// 	ret = -1;
	// else
	// {
	// 	ret = file_tell(fd);
	// }
	// return ret;
}

void sys_close(struct intr_frame *f)
{
	printf("close\n");
	// int ret;
	// int fd;
	// pop_stack(f->esp, &fd, 2);
	// if (fd < 0)
	// 	ret = -1;
	// else
	// {
	// 	ret = file_close(fd);
	// }
	// return ret;
}

void sys_read(struct intr_frame *f)
{
	printf("read\n");
}

void sys_write(struct intr_frame *f)
{
	printf("write\n");
	int ret;
	int size;
	void *buffer;
	int fd;

	pop_stack(f->esp, &size, 7);
	pop_stack(f->esp, &buffer, 6);
	pop_stack(f->esp, &fd, 5);

	if (!is_valid_addr(buffer))
		ret = -1;

	if (fd == 1)
	{
		putbuf(buffer, size);
		ret = size;
	}
	// else
	// {
	// 	enum intr_level old_level = intr_disable();
	// 	struct process_file *pf = search_fd(&thread_current()->opened_files, fd);
  //   struct file *file = pf->ptr;
  //   {
  //     /* data */
  //   };
    
	// 	intr_set_level (old_level);

	// 	if (pf == NULL)
	// 		ret = -1;
	// 	else
	// 	{
	// 		// lock_acquire(&filesys_lock);
	// 		ret = file_write(pf->ptr, buffer, size);
	// 		// lock_release(&filesys_lock);
	// 	}
	// }

	return ret;
}


static void syscall_handler (struct intr_frame *f UNUSED) 
{
  	printf ("system call!\n");
    // esp: pointer of the next-command, so syscall_number is the current command
	// get and check syscall_number
	int syscall_number = * (int *)f->esp;
	printf("syscall_number: %d\n", syscall_number);
	if(syscall_number <= 0 || syscall_number >= MAX_SYSCALL){
		printf("syscall_number error\n");
		thread_exit();
	}
	// operate syscall
	syscalls[syscall_number](f);
	thread_exit();
}