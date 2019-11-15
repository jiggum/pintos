#include <debug.h>
#include <stdio.h>
#include "vm/frame.h"
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "vm/page.h"

static unsigned hash_func (const struct hash_elem *e, void *aux);
static bool less_func(const struct hash_elem *left, const struct hash_elem *right, void *aux);
static struct frame_table_entry* get_next_evict_frame(uint32_t *pagedir);

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

void
frame_init ()
{
  hash_init(&frame_table, hash_func, less_func, NULL);
  list_init(&frame_list);
}

void*
frame_allocate(enum palloc_flags flags, void* upage)
{
  struct thread *cur = thread_current ();
  void *ppage = palloc_get_page(flags);

  if (ppage == NULL) {
    struct frame_table_entry *evict_frame = get_next_evict_frame(cur->pagedir);
    pagedir_clear_page(evict_frame->pd, evict_frame->upage);
    struct page_table_entry* pte = page_table_append(&cur->page_table, evict_frame->upage);
    pte->swap_slot = swap_out(evict_frame->ppage);
    frame_free_with_ppage(evict_frame->ppage);
    ppage = palloc_get_page(flags);
  }

  if (ppage == NULL) PANIC ("ppage from frame_allocate is NULL");

  struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));
  if (fte == NULL) PANIC ("fte from malloc is NULL");

  fte->upage = upage;
  fte->ppage = ppage;
  fte->pd = cur->pagedir;
  hash_insert (&frame_table, &fte->elem);
  list_push_back(&frame_list, &fte->elem_l);

  return ppage;
}

void
frame_free(void *ppage)
{
  struct frame_table_entry fte_query;
  struct frame_table_entry *fte;
  struct hash_elem *elem;
  fte_query.ppage = ppage;
  elem = hash_find(&frame_table, &fte_query.elem);
  if (elem == NULL) return;
  fte = hash_entry(elem, struct frame_table_entry, elem);
  hash_delete(&frame_table, &fte->elem);
  list_remove(&fte->elem_l);
  free(fte);
}

void
frame_free_with_ppage(void *ppage)
{
  frame_free(ppage);
  palloc_free_page(ppage);
}

static struct frame_table_entry*
get_next_evict_frame(uint32_t *pagedir)
{
  if(frame_list_evict_pointer == NULL) frame_list_evict_pointer = list_begin(&frame_list);

  while (true)
  {
    struct frame_table_entry *fte = list_entry (frame_list_evict_pointer, struct frame_table_entry, elem_l);

    frame_list_evict_pointer = list_next(frame_list_evict_pointer);
    if (frame_list_evict_pointer == list_end(&frame_list)) {
      frame_list_evict_pointer = list_begin(&frame_list);
    }

    if(!pagedir_is_accessed(pagedir, fte->upage)) return fte;
    pagedir_set_accessed(pagedir, fte->upage, false);
  }
}
