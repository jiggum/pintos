#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "lib/user/syscall.h"

static void syscall_handler (struct intr_frame *);
static int get_syscall_argc(int syscall);
static uintptr_t syscall_switch(struct intr_frame *);
static void validate_addr(const void *addr, size_t size);
static void halt_ ();
static void exit_ (int status);
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
      exit_(*(int *)arg[0]);
      break;
    case SYS_EXEC:
      validate_addr(*(char **)arg[0], sizeof(char *));
      return exec_(*(char **)arg[0]);
    case SYS_WAIT:
      return wait_(*(pid_t *)arg[0]);
    case SYS_CREATE:
      return create_(
        *(char **)arg[0],
        *(unsigned int *)arg[1]
      );
    case SYS_REMOVE:
      return remove_(*(char **)arg[0]);
    case SYS_OPEN:
      return open_(*(char **)arg[0]);
    case SYS_FILESIZE:
      return filesize_(*(int *)arg[0]);
    case SYS_READ:
      return read_(
        *(int *)arg[0],
        *(void **)arg[1],
        *(unsigned int *)arg[2]
      );
    case SYS_WRITE:
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
  ) exit_(-1);
}

static void
halt_ () {
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

static void
exit_ (int status) {
  struct thread *cur = thread_current ();

  cur->exit_status = status;

  if (cur->tid == cur->parent->wait_tid) {
    list_remove(&cur->child_elem);
    sema_up(&cur->parent->child_sema);
  }

  printf("%s: exit(%d)\n",thread_name(), status);
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

}

static bool
remove_ (const char *file)
{

}

static int
open_ (const char *file)
{

}

static int
filesize_ (int fd)
{

}

static int
read_ (int fd, void *buffer, unsigned size)
{

}

static int
write_ (int fd, const void *buffer, unsigned size) {
  if (fd == 0) return -1;
  putbuf(buffer, size);
  return (int)size;
}

static void
seek_ (int fd, unsigned position)
{

}

static unsigned
tell_ (int fd)
{

}

static void
close_ (int fd)
{

}
