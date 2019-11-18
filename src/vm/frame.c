#include <debug.h>
#include <stdio.h>
#include "vm/frame.h"
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "lib/string.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "vm/swap.h"
#include "vm/page.h"

static unsigned hash_func (const struct hash_elem *e, void *aux);
static bool less_func(const struct hash_elem *left, const struct hash_elem *right, void *aux);
static struct frame_table_entry* get_next_evict_frame(void);
static struct frame_table_entry* frame_find(void *ppage);
static struct frame_table_entry* frame_create(void* ppage, void* upage, struct thread* thread, bool pinned);
static void frame_update(struct frame_table_entry* fte, void* upage, struct thread* thread, bool pinned);

static struct hash frame_table;
static struct list frame_list;
struct list_elem* frame_list_evict_pointer;

static unsigned hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_table_entry *fte = hash_entry(elem, struct frame_table_entry, elem);
  return hash_bytes(&fte->ppage, sizeof(fte->ppage));
}

static bool
less_func(const struct hash_elem *left, const struct hash_elem *right, void *aux UNUSED)
{
  struct frame_table_entry *ftel = hash_entry(left, struct frame_table_entry, elem);
  struct frame_table_entry *fter = hash_entry(right, struct frame_table_entry, elem);
  return ftel->ppage < fter->ppage;
}

static struct frame_table_entry*
frame_create(void* ppage, void* upage, struct thread* thread, bool pinned)
{
  struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));
  fte->ppage = ppage;
  fte->upage = upage;
  fte->thread = thread;
  fte->pinned = pinned;
  return fte;
}

static void
frame_update(struct frame_table_entry* fte, void* upage, struct thread* thread, bool pinned)
{
  fte->upage = upage;
  fte->thread = thread;
  fte->pinned = pinned;
}

void
frame_init (void)
{
  hash_init(&frame_table, hash_func, less_func, NULL);
  list_init(&frame_list);
  lock_init(&frame_lock);
}

void*
frame_allocate(enum palloc_flags flags, void* upage)
{
  lock_acquire(&frame_lock);
  struct frame_table_entry *fte;
  struct thread *cur = thread_current ();
  void *ppage = palloc_get_page(flags);

  if (ppage == NULL) {
    struct frame_table_entry *evict_frame = get_next_evict_frame();
    pagedir_clear_page(evict_frame->thread->pagedir, evict_frame->upage);
    struct page_table_entry* pte = page_table_append(&evict_frame->thread->page_table, evict_frame->upage);
    // page_table_append return old pte if that has same upage.
    // swap_out not need to be called if the old pte's state is PAGE_FILE and readonly
    if (pte->state != PAGE_FILE || pte->file_writable) swap_out(pte, evict_frame->ppage, evict_frame->thread->pagedir);
    fte = frame_find(evict_frame->ppage);
    frame_update(fte, upage, cur, false);
    ppage = fte->ppage;
    palloc_format (ppage, flags);
  } else {
    fte = frame_create(ppage, upage, cur, false);
    hash_insert (&frame_table, &fte->elem);
    list_push_back(&frame_list, &fte->elem_l);
  }
  lock_release(&frame_lock);

  return ppage;
}

void
frame_free(void *ppage)
{
  struct frame_table_entry *fte = frame_find(ppage);
  if (fte == NULL) return;
  hash_delete(&frame_table, &fte->elem);
  list_remove(&fte->elem_l);
  free(fte);
  palloc_free_page(ppage);
}

static struct frame_table_entry*
frame_find(void *ppage)
{
  struct frame_table_entry fte_query;
  struct hash_elem *elem;
  fte_query.ppage = ppage;
  elem = hash_find(&frame_table, &fte_query.elem);
  if (elem == NULL) return NULL;
  return hash_entry(elem, struct frame_table_entry, elem);
}

static struct frame_table_entry*
get_next_evict_frame(void)
{
  if(frame_list_evict_pointer == NULL) frame_list_evict_pointer = list_begin(&frame_list);

  while (true)
  {
    struct frame_table_entry *fte = list_entry (frame_list_evict_pointer, struct frame_table_entry, elem_l);

    frame_list_evict_pointer = list_next(frame_list_evict_pointer);
    if (frame_list_evict_pointer == list_end(&frame_list)) {
      frame_list_evict_pointer = list_begin(&frame_list);
    }

    if (fte->pinned) continue;

    if(!pagedir_is_accessed(fte->thread->pagedir, fte->upage)) return fte;
    pagedir_set_accessed(fte->thread->pagedir, fte->upage, false);
  }
}

void
frames_preload(void *buffer, size_t size)
{
  void *upage_first = pg_round_down (buffer);
  void * upage;
  void * ppage;
  uint32_t *pd = thread_current()->pagedir;

  for (upage = upage_first; upage < buffer + size; upage += PGSIZE)
  {
    ppage = pagedir_get_page(pd, upage);
    if (ppage == NULL) {
      page_table_append(&thread_current()->page_table, upage);
      frame_load(upage);
    }
  }
}

void
frames_set_pinned(void *buffer, size_t size, bool pinned)
{
  void *upage_first = pg_round_down (buffer);
  void * upage;
  void * ppage;
  struct frame_table_entry* fte;
  uint32_t *pd = thread_current()->pagedir;

  for (upage = upage_first; upage < buffer + size; upage += PGSIZE)
  {
    ppage = pagedir_get_page(pd, upage);
    ASSERT(ppage != NULL);
    fte = frame_find(ppage);
    ASSERT(fte != NULL);
    fte->pinned = pinned;
  }
}

bool
frame_load(void *upage)
{
  struct thread *cur = thread_current ();
  struct page_table_entry *pte = page_table_find(&cur->page_table, upage);
  if(pte == NULL) goto FAIL;
  void *ppage = frame_allocate(PAL_USER, upage);
  if(ppage == NULL) PANIC ("frame_allocate returned null");
  bool writable = pte->state == PAGE_FILE ? pte->file_writable : true;
  if(!install_page(pte->upage, ppage, writable)) PANIC ("pagedir_set_page returned false");
  switch (pte->state) {
    case PAGE_SWAP:
      swap_in(pte, ppage, thread_current()->pagedir);
      break;
    case PAGE_FILE:
      page_file_load(pte, ppage);
      break;
    default:
      break;
  }

  if (pte->state != PAGE_FILE) page_table_remove(&cur->page_table, pte);
  return true;

  FAIL:
    return false;
};
