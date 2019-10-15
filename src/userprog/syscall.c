#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/user/syscall.h"

static void syscall_handler (struct intr_frame *);
static int get_syscall_argc(int syscall);
static uintptr_t syscall_switch(struct intr_frame *);
static void validate_addr(const void *addr, size_t size);
static void halt_ (void);
static pid_t exec_ (const char *file);
static int wait_ (pid_t pid);
static bool create_ (const char *file, unsigned initial_size);
static bool remove_ (const char *file);
static int open_ (const char *file);
static int filesize_ (int fd);
static int read_ (int fd, void *buffer, unsigned size);
static int write_ (int fd, const void *buffer, unsigned size);
static void seek_ (int fd, unsigned position);
static unsigned tell_ (int fd);
static void close_ (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
//  printf ("system call : %d\n",*(uintptr_t *)f->esp);
//  hex_dump((uintptr_t)f->esp, f->esp, 100, true);
  f->eax = syscall_switch(f);
}

static int
get_syscall_argc(int syscall)
{
  switch (syscall){
    case SYS_HALT:
      return 0;
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
      return 1;
    case SYS_CREATE:
    case SYS_SEEK:
      return 2;
    case SYS_READ:
    case SYS_WRITE:
      return 3;
    default:
      return -1;
  }
}

static uintptr_t
syscall_switch (struct intr_frame *f)
{
  validate_addr(f->esp, sizeof(uintptr_t *));
  int syscall = *(uintptr_t *)f->esp;
  int syscall_argc = get_syscall_argc(syscall);
  int i;
  uintptr_t *addr;
  ASSERT(syscall_argc >= 0);
  uintptr_t *arg[3];

  for(i = 0; i < syscall_argc; i++) {
    addr = f->esp + ((i + 1) * 4);
    validate_addr(addr, sizeof(uintptr_t *));
    arg[i] = (uintptr_t *)addr;
  }

  switch (syscall){
    case SYS_HALT:
      halt_();
      break;
    case SYS_EXIT:
      syscall_exit (*(int *)arg[0]);
      break;
    case SYS_EXEC:
      validate_addr(*(char **)arg[0], sizeof(char *));
      return exec_(*(char **)arg[0]);
    case SYS_WAIT:
      return wait_(*(pid_t *)arg[0]);
    case SYS_CREATE:
      validate_addr(*(char **)arg[0], sizeof(char *));
      return create_(
        *(char **)arg[0],
        *(unsigned int *)arg[1]
      );
    case SYS_REMOVE:
      validate_addr(*(char **)arg[0], sizeof(char *));
      return remove_(*(char **)arg[0]);
    case SYS_OPEN:
      validate_addr(*(char **)arg[0], sizeof(char *));
      return open_(*(char **)arg[0]);
    case SYS_FILESIZE:
      return filesize_(*(int *)arg[0]);
    case SYS_READ:
      validate_addr(*(void **)arg[1], sizeof(void *));
      return read_(
        *(int *)arg[0],
        *(void **)arg[1],
        *(unsigned int *)arg[2]
      );
    case SYS_WRITE:
      validate_addr(*(void **)arg[1], sizeof(void *));
      return write_(
        *(int *)arg[0],
        *(void **)arg[1],
        *(unsigned int *)arg[2]
      );
    case SYS_SEEK:
      seek_(
        *(int *)arg[0],
        *(unsigned int *)arg[1]
      );
      break;
    case SYS_TELL:
      return tell_(*(int *)arg[0]);
    case SYS_CLOSE:
      close_(*(int *)arg[0]);
      break;
    default:
      return 0;
  }
  return 0;
}

static void
validate_addr(const void *addr, size_t size) {
  const void *addr_last_byte = addr + size - 1;
  if (
    !is_user_vaddr(addr) ||
    !is_user_vaddr(addr_last_byte) ||
    !pagedir_get_page(thread_current()->pagedir, addr) ||
    !pagedir_get_page(thread_current()->pagedir, addr_last_byte)
  ) syscall_exit(-1);
}

static void
halt_ (void) {
  shutdown_power_off();
}

static pid_t
exec_ (const char *cmd_line)
{
  struct cmd *cmd;

  cmd = palloc_get_page (0);
  if (
    !cmd_init(cmd, cmd_line) ||
    !filesys_lookup(cmd->name)
  ) goto error;
  free_cmd(cmd);

  return process_execute(cmd_line);

  error:
    if (cmd) free_cmd (cmd);
    return -1;
}

void
syscall_exit (int status) {
  struct thread *cur = thread_current ();

  cur->exit_status = status;

  printf("%s: exit(%d)\n",thread_name(), status);

  if (cur->tid == cur->parent->wait_tid) {
    sema_up(&cur->parent->child_sema);
  }
  list_remove(&cur->child_elem);
  sema_down(&cur->child_sema);
  thread_exit ();
}

static int
wait_ (pid_t pid)
{
  return process_wait(pid);
}

static bool
create_ (const char *file, unsigned initial_size)
{
  return filesys_create(file, initial_size);
}

static bool
remove_ (const char *file)
{
  return filesys_remove(file);
}

static int
open_ (const char *file)
{
  struct thread *cur = thread_current ();
  struct file* file_ = filesys_open(file);
  if (file_ == NULL) goto error;
  struct file_descriptor *file_d = malloc(sizeof(*file_d));

  file_descriptor_init(file_d, file_, get_next_fd(cur));
  list_insert_ordered(&cur->file_descriptors, &file_d -> elem, compare_fd_less, NULL);
  return file_d->fd;

  error:
    return -1;
}

static int
filesize_ (int fd)
{
  struct file_descriptor *file_d = get_file_descriptor(fd);
  return file_length(file_d->file);
}

static int
read_ (int fd, void *buffer, unsigned size)
{
  if (fd == 0) {
    unsigned i;
    for(i = 0; i < size; i++) {
      ((uint8_t *)buffer)[i] = input_getc();
    }
    return (int)size;
  } else {
    struct file_descriptor *file_d = get_file_descriptor(fd);
    if (file_d == NULL) goto error;
    return file_read (file_d->file, buffer, size);
  }

  error:
    return -1;
}

static int
write_ (int fd, const void *buffer, unsigned size) {
  if (fd == 0) goto error;
  if (fd == 1) {
    putbuf(buffer, size);
    return (int) size;
  }
  struct file_descriptor *file_d = get_file_descriptor(fd);
  if (file_d == NULL) goto error;
  return file_write(file_d->file, buffer, size);

  error:
    return -1;
}

static void
seek_ (int fd, unsigned position)
{
  struct file_descriptor *file_d = get_file_descriptor(fd);
  file_seek(file_d->file, position);
}

static unsigned
tell_ (int fd)
{
  struct file_descriptor *file_d = get_file_descriptor(fd);
  return file_tell(file_d->file);
}

static void
close_ (int fd)
{
  struct file_descriptor *file_d = get_file_descriptor(fd);
  if (file_d == NULL) return;
  file_close(file_d->file);
  list_remove(&file_d->elem);
  free(file_d);
}
