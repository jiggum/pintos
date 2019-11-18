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
#include "vm/frame.h"
#include "vm/page.h"

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
static mapid_t mmap_ (int fd, void *addr);
static void munmap_ (mapid_t mapid);
static int get_user (const uint8_t *uaddr);
static bool validate_user(const uint8_t *uaddr);

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
    case SYS_MMAP:
      return 2;
    case SYS_MUNMAP:
      return 1;
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
    case SYS_MMAP:
      return mmap_(
        *(int *)arg[0],
        *(void **)arg[1]
      );
    case SYS_MUNMAP:
      munmap_(*(mapid_t *)arg[0]);
      break;
    default:
      break;
  }
  return 0;
}

static void
validate_addr(const void *addr, size_t size) {
  const void *addr_last_byte = addr + size - 1;
  if (validate_user(addr)) validate_user(addr_last_byte);
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
    syscall_lock_release();
    res = -1;
    goto done;
  } else {
    syscall_lock_release();
  }
  res = process_execute(cmd_line);

  done:
    free_cmd (cmd);
    return res;
}

void
syscall_exit (int status) {
  struct thread *cur = thread_current ();

  printf("%s: exit(%d)\n",thread_name(), status);
  cur->pcb->exit_status = status;

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
  syscall_lock_acquire();
  bool res = filesys_create(file, initial_size);
  syscall_lock_release();
  return res;
}

static bool
remove_ (const char *file)
{
  syscall_lock_acquire();
  bool res = filesys_remove(file);
  syscall_lock_release();
  return res;
}

static int
open_ (const char *file)
{
  syscall_lock_acquire();
  struct thread *cur = thread_current ();
  struct file* file_ = filesys_open(file);
  if (file_ == NULL) goto error;
  struct file_descriptor *file_d = malloc(sizeof(struct file_descriptor));

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
  syscall_lock_acquire();
  struct file_descriptor *file_d = get_file_descriptor(fd);
  off_t res = file_length(file_d->file);
  syscall_lock_release();
  return res;
}

static int
read_ (int fd, void *buffer, unsigned size)
{
  int res;
  syscall_lock_acquire();
  frames_preload(buffer, size);
  frames_set_pinned(buffer, size, true);
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
    frames_set_pinned(buffer, size, false);
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
  syscall_lock_acquire();
  struct file_descriptor *file_d = get_file_descriptor(fd);
  file_seek(file_d->file, position);
  syscall_lock_release();
}

static unsigned
tell_ (int fd)
{
  syscall_lock_acquire();
  struct file_descriptor *file_d = get_file_descriptor(fd);
  int res = file_tell(file_d->file);
  syscall_lock_release();
  return res;
}

static void
close_ (int fd)
{
  syscall_lock_acquire();
  struct file_descriptor *file_d = get_file_descriptor(fd);
  if (file_d == NULL) {
    syscall_lock_release();
    return;
  }
  file_close(file_d->file);
  list_remove(&file_d->elem);
  free(file_d);
  syscall_lock_release();
}

static mapid_t
mmap_ (int fd, void *addr)
{
  syscall_lock_acquire();
  struct file_descriptor *file_d = get_file_descriptor(fd);
  if (file_d == NULL) goto error;
  struct file *file = file_reopen(file_d->file);
  struct thread *cur = thread_current ();
  struct mmap_descriptor *mmap_d = malloc(sizeof(struct mmap_descriptor));
  mmap_descriptor_init(mmap_d, get_next_md(cur), file);
  off_t file_size = file_length(file);
  for (off_t ofs = 0; ofs < file_size; ofs += PGSIZE) {
    uint32_t page_read_bytes = file_size - ofs > PGSIZE ? PGSIZE : file_size - ofs;
    uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
    void* upage = addr + ofs;
    struct page_table_entry* pte = page_table_append(&thread_current()->page_table, upage);
    page_file_map(pte, file, ofs, page_read_bytes, page_zero_bytes, true);
    list_push_back (&mmap_d->ptes, &pte->md_elem);
  }

  list_insert_ordered(&cur->mmap_descriptors, &mmap_d->elem, compare_md_less, NULL);
  syscall_lock_release();
  return mmap_d->md;

  error:
    syscall_lock_release();
    return -1;
}

static void
munmap_ (mapid_t mapid)
{
  syscall_lock_acquire();
  struct mmap_descriptor *mmap_d = get_mmap_descriptor(mapid);
  ASSERT(mmap_d != NULL);
  free_mmap_descriptor(mmap_d);
  syscall_lock_release();
}

void
syscall_lock_acquire (void)
{
  lock_acquire(&lock);
}

void
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

static bool
validate_user(const uint8_t *uaddr) {
  if ((void*)uaddr >= PHYS_BASE || get_user(uaddr) == -1) {
    syscall_exit(-1);
    return false;
  }
  return true;
}
