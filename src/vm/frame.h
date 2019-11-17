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
  bool pinned;
};

void frame_init (void);
void* frame_allocate(enum palloc_flags, void* upage);
void frame_free(void *ppage);
void frames_preload(void *buffer, size_t size);
void frames_set_pinned(void *addr, size_t size, bool pinned);
bool frame_load(void *upage);

struct lock frame_lock;
