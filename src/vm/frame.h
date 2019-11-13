#ifndef PINTOS_FRAME_H
#define PINTOS_FRAME_H
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#endif

struct frame_table_entry {
  void *upage;
  void *ppage;
  struct hash_elem elem;
};

void frame_init ();
void* frame_allocate(enum palloc_flags, void* upage);
void frame_free(void *ppage);
