#ifndef PINTOS_FRAME_H
#define PINTOS_FRAME_H
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#endif

struct frame_table_entry {
  void *upage;
  void *ppage;
  struct hash_elem elem;
  struct list_elem elem_l;
  struct thread *thread;
};

void frame_init ();
void* frame_allocate(enum palloc_flags, void* upage);
void frame_free(void *ppage);
void frame_free_with_ppage(void *ppage);

struct lock frame_lock;
