#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h" // for lock
#include "filesys/file.h"
#include <stdlib.h>

static struct lock filesys_lock;

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
void sys_exit(struct intr_frame *f);
void sys_exec(struct intr_frame *f);
void sys_wait(struct intr_frame *f);

/* System call for file. */
void sys_create(struct intr_frame *f);
void sys_remove(struct intr_frame *f);
void sys_open(struct intr_frame *f);
void sys_filesize(struct intr_frame *f);
void sys_read(struct intr_frame *f);
void sys_write(struct intr_frame *f);
void sys_seek(struct intr_frame *f);
void sys_tell(struct intr_frame *f);
void sys_close(struct intr_frame *f);

void *is_valid_addr(const void *user_addr)
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
    [SYS_CLOSE] = sys_close};

static void syscall_handler(struct intr_frame *);
struct thread_file *find_file_id(int file_id);

void *is_valid_addr_range(const void *user_addr, size_t size)
{
  const uint8_t *start = user_addr;
  const uint8_t *end = start + size;

  for (const uint8_t *ptr = start; ptr < end; ptr++)
  {
    if (!is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
    {
      thread_current()->st_exit = -1;
      thread_exit();
    }
  }
  return pagedir_get_page(thread_current()->pagedir, user_addr);
}

/* Find file by the file's ID */
struct thread_file *
find_file_id(int file_id)
{
  struct thread *t = thread_current();
  struct list *files = &t->files;

  // check if the list is empty
  if (list_empty(files))
    return NULL;

  struct list_elem *e;
  struct thread_file *thread_file_temp = NULL;

  for (e = list_begin(files); e != list_end(files); e = list_next(e))
  {
    if (e == NULL)
      continue;

    thread_file_temp = list_entry(e, struct thread_file, file_elem);
    if (thread_file_temp != NULL && file_id == thread_file_temp->fd && !thread_file_temp->closed)
      return thread_file_temp;
  }
  return NULL;
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

/* System Call: void halt (void)
    Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h).
*/
void sys_halt(void)
{
  shutdown_power_off();
}

void sys_exit(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;             // get current user addr
  is_valid_addr(user_ptr + 1);             // check if the next uaddr valid
  int exit_status = *(user_ptr + 1);       // get exit status
  thread_current()->st_exit = exit_status; // set exit status
  thread_exit();
}

void sys_exec(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  is_valid_addr(user_ptr + 1); // check if the next uaddr valid
  is_valid_addr(*(user_ptr + 1));            // check if the file name valid
  char *file_name = (char *)*(user_ptr + 1); // get file name
  f->eax = process_execute(file_name);       // execute the file
}

void sys_wait(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  is_valid_addr (user_ptr + 1);
  *user_ptr++;
  f->eax = process_wait(*user_ptr);
}

void sys_create(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  is_valid_addr(user_ptr + 1); // check if the next uaddr valid
  is_valid_addr(user_ptr + 2); // check if the file name valid

  char *file_name = (char *)*(user_ptr + 1); // get file name
  unsigned initial_size = *(user_ptr + 2);

  is_valid_addr(file_name); // validate file_name string

  acquire_lock_f();
  bool success = filesys_create(file_name, initial_size);
  release_lock_f();

  f->eax = success ? 1 : 0; // true or false// check if the file name is valid

  // output
  //printf("(write-normal) create \"%s\"\n", file_name);
}

void sys_remove(struct intr_frame *f)
{	
	// print("remove\n") ;
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
  uint32_t *user_ptr = f->esp;
  is_valid_addr(user_ptr + 1);
  char *file_name = (char *)*(user_ptr + 1);
  is_valid_addr(file_name);

  acquire_lock_f();
  struct file *opened_file = filesys_open(file_name);
  release_lock_f();

  if (opened_file == NULL)
  {
    f->eax = -1;
    return;
  }

  struct thread *cur = thread_current();
  ASSERT(is_thread(cur));

  // Allocate memory for file structure
  struct thread_file *t_file = malloc(sizeof(struct thread_file));
  if (t_file == NULL)
  {
    file_close(opened_file);
    f->eax = -1;
    return;
  }

  // Fully initialize t_file structure
  memset(t_file, 0, sizeof(struct thread_file));
  t_file->file = opened_file;
  t_file->fd = cur->max_file_fd++;
  t_file->closed = false;

  //printf("[DEBUG] %s: open fd=%d (%s)\n", thread_name(), t_file->fd, file_name);
  
  // Safely add file to thread's file list
  list_push_back(&cur->files, &t_file->file_elem);

  f->eax = t_file->fd;
}

void sys_filesize(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  int fd = *(user_ptr + 1);

  struct thread_file *t_file = find_file_id(fd);
  if (t_file == NULL || t_file->closed)
  {
    f->eax = -1; // File doesn't exist or is closed
    return;
  }

  acquire_lock_f();
  off_t size = file_length(t_file->file); // Get the file size
  release_lock_f();
  f->eax = size; // success
  //printf("[DEBUG] %s: filesize fd=%d size=%d\n", thread_name(), fd, size);
}

void sys_seek(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  int fd = *(user_ptr + 1);
  unsigned position = *(user_ptr + 2);

  struct thread_file *t_file = find_file_id(fd);
  if (t_file == NULL || t_file->closed)
  {
    f->eax = -1; // File doesn't exist or is closed
    return;
  }

  acquire_lock_f();
  file_seek(t_file->file, position); // Seek to the specified position
  release_lock_f();
  //printf("[DEBUG] %s: seek fd=%d to position=%u\n", thread_name(), fd, position);
}

void sys_tell(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  int fd = *(user_ptr + 1);

  struct thread_file *t_file = find_file_id(fd);
  if (t_file == NULL || t_file->closed)
  {
    f->eax = -1; // File doesn't exist or is closed
    return;
  }

  acquire_lock_f();
  off_t position = file_tell(t_file->file); // Get the current position
  release_lock_f();
  f->eax = position; // success
}

void sys_close(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  int fd = *(user_ptr + 1);

  struct thread_file *t_file = find_file_id(fd);
  if (t_file != NULL && !t_file->closed)
  {
    acquire_lock_f();
    file_close(t_file->file);
    release_lock_f();

    t_file->closed = true;           // mark as closed
    list_remove(&t_file->file_elem); // remove from list
    free(t_file);                    // free the struct
  }
  else
  {
	f->eax = -1 ;
  }
  f->eax = 0; // success
}

void sys_read(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  int fd = *(user_ptr + 1);
  char *buffer = (char *)*(user_ptr + 2);
  unsigned size = *(user_ptr + 3);

  // Check parameters
  is_valid_addr_range(buffer, size);
  if  (fd == 0)
  {
    // Read from stdin
    for (unsigned i = 0; i < size; i++)
    {
      buffer[i] = input_getc();
    }
    f->eax = size;
    return; // Exit function here
  }
  // Handle invalid descriptors
  if (fd < 0 || fd == 1) // fd=1 is stdout, should not be read from
  {
    f->eax = -1;
    return;
  }
  // Find file and read from it
  struct thread_file *file = find_file_id(fd);
  if (file == NULL || file->closed)
  {
    f->eax = -1; // File doesn't exist or is closed
    return;
  }

  acquire_lock_f();
  // Read from the file
  int bytes_read = file_read(file->file, buffer, size); // for convenience and extension, use file_read
  release_lock_f();
  f->eax = bytes_read;
}

void sys_write(struct intr_frame *f)
{
  uint32_t *user_ptr = f->esp;
  int fd = *(user_ptr + 1);
  const char *buffer = (const char *)*(user_ptr + 2);
  off_t size = *(user_ptr + 3);

  // Check parameters
  is_valid_addr_range(buffer, size);
  if (size < 0)
  {
    f->eax = -1;
    return;
  }

  // Handle stdout
  if (fd == 1)
  {
    putbuf(buffer, size);
    f->eax = size;
    return;  // Exit function here
  }

  // Handle invalid descriptors
  if (fd <= 0)  // fd 0 is stdin, should not be written to
  {
    f->eax = -1;
    return;
  }

  // Find file and write to it
  struct thread_file *file = find_file_id(fd);
  if (file != NULL && !file->closed)
  {
    acquire_lock_f();
    f->eax = file_write(file->file, buffer, size);
    release_lock_f();
  }
  else
  {
    f->eax = -1;  // File doesn't exist or is closed
  }
}

static void syscall_handler(struct intr_frame *f UNUSED)
{
  int *esp = f->esp;
  is_valid_addr(esp); // check if the esp is valid
                      // esp: pointer of the next-command, so syscall_number is the current command
  // get and check syscall_number
  int syscall_num = *esp;
  if (syscall_num <= 0 || syscall_num >= MAX_SYSCALL)
  {
    thread_exit();
  }
  // operate syscall
  syscalls[syscall_num](f);
}
