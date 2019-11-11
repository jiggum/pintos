#include <debug.h>
#include "vm/frame.h"
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

static unsigned hash_func (const struct hash_elem *e, void *aux);
static bool less_func(const struct hash_elem *left, const struct hash_elem *right, void *aux);

static struct hash frame_table;

static unsigned hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_table_entry *fte = hash_entry(elem, struct frame_table_entry, elem);
  return hash_bytes(&fte->ppage, sizeof fte->ppage);
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
}

void*
frame_allocate(enum palloc_flags flags)
{
  void *upage = palloc_get_page(flags);
  struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));

  if (upage == NULL) PANIC ("page from palloc_get_page is NULL");
  if (fte == NULL) PANIC ("fte from malloc is NULL");

  fte->upage = upage;
  fte->ppage = (void *)vtop(upage);
  hash_insert (&frame_table, &fte->elem);

  return upage;
}

void
frame_free(void *upage)
{
  struct frame_table_entry fte_query;
  struct frame_table_entry *fte;
  struct hash_elem *elem;
  fte_query.ppage = (void *)vtop(upage);
  elem = hash_find(&frame_table, &fte_query.elem);
  ASSERT(elem != NULL);
  fte = hash_entry(elem, struct frame_table_entry, elem);
  hash_delete(&frame_table, &fte->elem);
  palloc_free_page(fte->upage);
  free(fte);
}
