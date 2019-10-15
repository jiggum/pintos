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
static void syscall_switch(struct intr_frame *);
static void validate_addr(const void *addr, size_t size);
static void halt_ (void);
static void exec_ (const char *file, struct intr_frame *f);
static void wait_ (pid_t pid, struct intr_frame *f);
static void create_ (const char *file, unsigned initial_size, struct intr_frame *f);
static void remove_ (const char *file, struct intr_frame *f);
static void open_ (const char *file, struct intr_frame *f);
static void filesize_ (int fd, struct intr_frame *f);
static void read_ (int fd, void *buffer, unsigned size, struct intr_frame *f);
static void write_ (int fd, const void *buffer, unsigned size, struct intr_frame *f);
static void seek_ (int fd, unsigned position);
static void tell_ (int fd, struct intr_frame *f);
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
  syscall_switch(f);
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

static void
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
      exec_(*(char **)arg[0], f);
      break;
    case SYS_WAIT:
      wait_(*(pid_t *)arg[0], f);
      break;
    case SYS_CREATE:
      validate_addr(*(char **)arg[0], sizeof(char *));
      create_(
        *(char **)arg[0],
        *(unsigned int *)arg[1],
        f
      );
      break;
    case SYS_REMOVE:
      validate_addr(*(char **)arg[0], sizeof(char *));
      remove_(*(char **)arg[0], f);
      break;
    case SYS_OPEN:
      validate_addr(*(char **)arg[0], sizeof(char *));
      open_(*(char **)arg[0], f);
      break;
    case SYS_FILESIZE:
      filesize_(*(int *)arg[0], f);
      break;
    case SYS_READ:
      validate_addr(*(void **)arg[1], sizeof(void *));
      read_(
        *(int *)arg[0],
        *(void **)arg[1],
        *(unsigned int *)arg[2],
        f
      );
      break;
    case SYS_WRITE:
      validate_addr(*(void **)arg[1], sizeof(void *));
      write_(
        *(int *)arg[0],
        *(void **)arg[1],
        *(unsigned int *)arg[2],
        f
      );
      break;
    case SYS_SEEK:
      seek_(
        *(int *)arg[0],
        *(unsigned int *)arg[1]
      );
      break;
    case SYS_TELL:
      tell_(*(int *)arg[0], f);
      break;
    case SYS_CLOSE:
      close_(*(int *)arg[0]);
      break;
    default:
      break;
  }
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

static void
exec_ (const char *cmd_line, struct intr_frame *f)
{
  struct cmd *cmd;

  cmd = palloc_get_page (0);
  if (!cmd_init(cmd, cmd_line)) goto error;
  filesys_lock_acquire();
  if (!filesys_lookup(cmd->name)) {
    filesys_lock_release();
    goto error;
  } else filesys_lock_release();
  free_cmd(cmd);

  f->eax = process_execute(cmd_line);
  return;

  error:
    if (cmd) free_cmd (cmd);
    f->eax = -1;
}

void
syscall_exit (int status) {
  struct thread *cur = thread_current ();

  cur->exit_status = status;

  printf("%s: exit(%d)\n",thread_name(), status);

  sema_down(&cur->child_sema);
  sema_up(&cur->parent->parent_sema);
  sema_down(&cur->child_sema);
  thread_exit ();
}

static void
wait_ (pid_t pid, struct intr_frame *f)
{
  f->eax = process_wait(pid);
}

static void
create_ (const char *file, unsigned initial_size, struct intr_frame *f)
{
  filesys_lock_acquire();
  f->eax = filesys_create(file, initial_size);
  filesys_lock_release();
}

static void
remove_ (const char *file, struct intr_frame *f)
{
  filesys_lock_acquire();
  f->eax = filesys_remove(file);
  filesys_lock_release();
}

static void
open_ (const char *file, struct intr_frame *f)
{
  struct thread *cur = thread_current ();
  filesys_lock_acquire();
  struct file* file_ = filesys_open(file);
  filesys_lock_release();
  if (file_ == NULL) goto error;
  struct file_descriptor *file_d = malloc(sizeof(*file_d));

  file_descriptor_init(file_d, file_, get_next_fd(cur));
  list_insert_ordered(&cur->file_descriptors, &file_d -> elem, compare_fd_less, NULL);
  f->eax = file_d->fd;
  return;

  error:
    f->eax = -1;
}

static void
filesize_ (int fd, struct intr_frame *f)
{
  struct file_descriptor *file_d = get_file_descriptor(fd);
  filesys_lock_acquire();
  f->eax = file_length(file_d->file);
  filesys_lock_release();
}

void
read_ (int fd, void *buffer, unsigned size, struct intr_frame *f)
{
  if (fd == 0) {
    unsigned i;
    for(i = 0; i < size; i++) {
      ((uint8_t *)buffer)[i] = input_getc();
    }
    f->eax = (int)size;
  } else {
    struct file_descriptor *file_d = get_file_descriptor(fd);
    if (file_d == NULL) goto error;
    filesys_lock_acquire();
    f->eax = file_read (file_d->file, buffer, size);
    filesys_lock_release();
  }
  return;

  error:
    f->eax = -1;
}

static void
write_ (int fd, const void *buffer, unsigned size, struct intr_frame *f) {
  if (fd == 0) goto error;
  if (fd == 1) {
    putbuf(buffer, size);
    f->eax = (int) size;
    return;
  }
  struct file_descriptor *file_d = get_file_descriptor(fd);
  if (file_d == NULL) goto error;
  filesys_lock_acquire();
  f->eax = file_write(file_d->file, buffer, size);
  filesys_lock_release();
  return;

  error:
    f->eax = -1;
}

static void
seek_ (int fd, unsigned position)
{
  struct file_descriptor *file_d = get_file_descriptor(fd);
  filesys_lock_acquire();
  file_seek(file_d->file, position);
  filesys_lock_release();
}

static void
tell_ (int fd, struct intr_frame *f)
{
  struct file_descriptor *file_d = get_file_descriptor(fd);
  filesys_lock_acquire();
  f->eax = file_tell(file_d->file);
  filesys_lock_release();
}

static void
close_ (int fd)
{
  struct file_descriptor *file_d = get_file_descriptor(fd);
  if (file_d == NULL) return;
  filesys_lock_acquire();
  file_close(file_d->file);
  filesys_lock_release();
  list_remove(&file_d->elem);
  free(file_d);
}
