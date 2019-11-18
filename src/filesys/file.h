#ifndef FILESYS_FILE_H
#define FILESYS_FILE_H

#include "filesys/off_t.h"
#include <stdbool.h>
#include <debug.h>
#include "lib/kernel/list.h"
#include "vm/page.h"

typedef int mapid_t;

struct inode;

/* Opening and closing files. */
struct file *file_open (struct inode *);
struct file *file_reopen (struct file *);
void file_close (struct file *);
struct inode *file_get_inode (struct file *);

/* Reading and writing. */
off_t file_read (struct file *, void *, off_t);
off_t file_read_at (struct file *, void *, off_t size, off_t start);
off_t file_write (struct file *, const void *, off_t);
off_t file_write_at (struct file *, const void *, off_t size, off_t start);

/* Preventing writes. */
void file_deny_write (struct file *);
void file_allow_write (struct file *);

/* File position. */
void file_seek (struct file *, off_t);
off_t file_tell (struct file *);
off_t file_length (struct file *);

struct file_descriptor
{
  struct file *file;
  int fd;
  struct list_elem elem;
};

struct mmap_descriptor
{
  mapid_t md;
  struct file *file;
  struct list_elem elem;
  struct list ptes;
};

void file_descriptor_init(struct file_descriptor *file_d, struct file *file, int fd);
bool compare_fd_less (const struct list_elem *left, const struct list_elem *right, void *aux);

void mmap_descriptor_init(struct mmap_descriptor *mmap_d, int md, struct file *file);
bool compare_md_less (const struct list_elem *left, const struct list_elem *right, void *aux UNUSED);

#endif /* filesys/file.h */
