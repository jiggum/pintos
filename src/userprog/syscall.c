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
static uint32_t syscall_switch(struct intr_frame *);
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
static void syscall_lock_acquire (void);
static void syscall_lock_release (void);
static int get_user (const uint8_t *uaddr);
static void validate_user(const uint8_t *uaddr);

struct lock lock;

void
syscall_init (void) 
{
  lock_init (&lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  thread_current()->esp = f->esp;
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

static uint32_t
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
      validate_user(*(uint8_t **)arg[0]);
      return exec_(*(char **)arg[0]);
    case SYS_WAIT:
      return wait_(*(pid_t *)arg[0]);
    case SYS_CREATE:
      validate_user(*(uint8_t **)arg[0]);
      validate_user(*(uint8_t **)arg[0] + *(unsigned int *)arg[1] - 1);
      return create_(
        *(char **)arg[0],
        *(unsigned int *)arg[1]
      );
    case SYS_REMOVE:
      validate_user(*(uint8_t **)arg[0]);
      return remove_(*(char **)arg[0]);
    case SYS_OPEN:
      validate_user(*(uint8_t **)arg[0]);
      return open_(*(char **)arg[0]);
    case SYS_FILESIZE:
      return filesize_(*(int *)arg[0]);
    case SYS_READ:
      validate_user(*(uint8_t **)arg[1]);
      validate_user(*(uint8_t **)arg[1] + *(unsigned int *)arg[2] - 1);
      return read_(
        *(int *)arg[0],
        *(void **)arg[1],
        *(unsigned int *)arg[2]
      );
    case SYS_WRITE:
      validate_user(*(uint8_t **)arg[1]);
      validate_user(*(uint8_t **)arg[1] + *(unsigned int *)arg[2] - 1);
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
      break;
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
  pid_t res;
  syscall_lock_acquire();
  struct cmd *cmd;

  cmd = palloc_get_page (0);
  if (
    !cmd_init(cmd, cmd_line) ||
    !filesys_lookup(cmd->name)
  ) {
    res = -1;
    goto done;
  }
  res = process_execute(cmd_line);

  done:
    free_cmd (cmd);
    syscall_lock_release();
    return res;
}

void
syscall_exit (int status) {
  struct thread *cur = thread_current ();

  printf("%s: exit(%d)\n",thread_name(), status);
  cur->pcb->exit_status = status;

  lock_acquire(&cur->pcb->lock);
  cur->pcb->exited = true;
  if (cur->pcb->waiting) sema_up(&cur->pcb->sema);
  lock_release(&cur->pcb->lock);

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
  syscall_lock_acquire();
  struct thread *cur = thread_current ();
  struct file* file_ = filesys_open(file);
  if (file_ == NULL) goto error;
  struct file_descriptor *file_d = malloc(sizeof(*file_d));

  file_descriptor_init(file_d, file_, get_next_fd(cur));
  list_insert_ordered(&cur->file_descriptors, &file_d -> elem, compare_fd_less, NULL);
  syscall_lock_release();
  return file_d->fd;

  error:
    syscall_lock_release();
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
  int res;
  syscall_lock_acquire();
  if (fd == 0) {
    unsigned i;
    for(i = 0; i < size; i++) {
      ((uint8_t *)buffer)[i] = input_getc();
    }
    res = (int)size;
  } else {
    struct file_descriptor *file_d = get_file_descriptor(fd);
    if (file_d == NULL) {
      res = -1;
      goto done;
    }
    res = file_read (file_d->file, buffer, size);
  }

  done:
    syscall_lock_release();
    return res;
}

static int
write_ (int fd, const void *buffer, unsigned size) {
  int res;
  syscall_lock_acquire();
  if (fd == 0) {
    res =  -1;
    goto done;
  }
  if (fd == 1) {
    putbuf(buffer, size);
    res = (int) size;
    goto done;
  }
  struct file_descriptor *file_d = get_file_descriptor(fd);
  if (file_d == NULL) {
    res =  -1;
    goto done;
  }
  res = file_write(file_d->file, buffer, size);

  done:
    syscall_lock_release();
    return res;
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

static void
syscall_lock_acquire (void)
{
  lock_acquire(&lock);
}

static void
syscall_lock_release (void)
{
  lock_release(&lock);
}

// pintod doc's 3.1.5
/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
  : "=&a" (result) : "m" (*uaddr));
  return result;
}

static void
validate_user(const uint8_t *uaddr) {
  if ((void*)uaddr >= PHYS_BASE || get_user(uaddr) == -1) syscall_exit(-1);
}
