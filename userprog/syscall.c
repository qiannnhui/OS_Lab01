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

static struct lock file_sys_lock;

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

void * is_valid_addr(const void *user_addr)
{
  // todo: still need to validate the content of page
  void *physical_addr = NULL;
  if (is_user_vaddr(user_addr))
    physical_addr = pagedir_get_page(thread_current()->pagedir, user_addr);
  // if not valid address (vaddr not valid or page not exist), exit
  if (physical_addr == NULL)
  {
    thread_current()->st_exit = -1;
    thread_exit();
  } 
  return physical_addr;
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

/* Find file by the file's ID */
// todo: old code
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
  uint32_t *user_ptr = f->esp; // get current user addr
  is_valid_addr(user_ptr + 1); // check if the next uaddr valid
  int exit_status = *(user_ptr + 1); // get exit status
  thread_current()->st_exit = exit_status; // set exit status
  thread_exit();
}

void sys_exec(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  is_valid_addr(user_ptr + 1); // check if the next uaddr valid
  is_valid_addr(*(user_ptr + 1)); // check if the file name valid
  char *file_name = (char *)*(user_ptr + 1); // get file name
  f->eax = process_execute(file_name); // execute the file
}

void sys_wait(struct intr_frame *f)
{
	printf("wait\n");
}

void 
sys_create(struct intr_frame* f)
{
	printf("create\n") ;
  uint32_t *user_ptr = f->esp;
  is_valid_addr (user_ptr + 5);
  is_valid_addr (*(user_ptr + 4));
  *user_ptr++;
  acquire_lock_f ();
  f->eax = filesys_create ((const char *)*user_ptr, *(user_ptr+1));
  release_lock_f ();
}

/* Do system remove, by calling the method filesys_remove */
void 
sys_remove(struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  is_valid_addr (user_ptr + 1);
  is_valid_addr (*(user_ptr + 1));
  *user_ptr++;
  acquire_lock_f ();
  f->eax = filesys_remove ((const char *)*user_ptr);
  release_lock_f ();
}

void sys_open(struct intr_frame *f)
{
	printf("open\n");
}

void sys_filesize(struct intr_frame *f)
{
	printf("filesize\n");
}

void sys_seek(struct intr_frame *f)
{
	printf("seek\n");
}

void sys_tell(struct intr_frame *f)
{
	printf("tell\n");
}

void sys_close(struct intr_frame *f)
{
	printf("close\n");
}

void sys_read(struct intr_frame *f)
{
	// printf("read\n");
	// todo: old code
  uint32_t *user_ptr = f->esp;
  is_valid_addr(user_ptr + 7);//for tests maybe?
  is_valid_addr(*(user_ptr + 6));
  *user_ptr++;
  int fd = *user_ptr;
  char * buffer = (const char *)*(user_ptr+1);
  off_t size = *(user_ptr+2);

  if (fd < 0 || fd == 1) {
		f->eax = -1;
		return -1;
	}
  
  if (fd == 0) {//writes to the console
    /* Use putbuf to do testing */
    for (int i = 0; i < size; i++)
      buffer[i] = input_getc();
    f->eax = size;//return number written
  }
  else
  {
    /* Write to Files */
    struct thread_file * thread_file_temp = find_file_id (*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f ();//file operating needs lock
      f->eax = file_read (thread_file_temp->file, buffer, size);
      release_lock_f ();
    } 
    else
    {
      f->eax = 0;//can't write,return 0
    }
  }
}

void sys_write (struct intr_frame* f)
{
  // todo: old code
  uint32_t *user_ptr = f->esp;
  is_valid_addr(user_ptr + 7);//for tests maybe?
  is_valid_addr(*(user_ptr + 6));
  *user_ptr++;
  int fd = *user_ptr;
  const char * buffer = (const char *)*(user_ptr+1);
  off_t size = *(user_ptr+2);

  if (fd <= 0) {
		f->eax = -1;
		return;
	}
  
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


static void syscall_handler (struct intr_frame *f UNUSED) 
{
  int *esp = f->esp;
  is_valid_addr(esp); // check if the esp is valid
  // esp: pointer of the next-command, so syscall_number is the current command
	// get and check syscall_number
	int syscall_num = *esp;
	if(syscall_num <= 0 || syscall_num >= MAX_SYSCALL){
		thread_exit();
	}
	// operate syscall
	syscalls[syscall_num](f);
}

