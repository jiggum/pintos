#include <debug.h>
#include <stdio.h>
#include "vm/page.h"
#include "vm/swap.h"
#include "lib/kernel/hash.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

static unsigned hash_func(const struct hash_elem *e, void *aux);
static bool less_func(const struct hash_elem *left, const struct hash_elem *right, void *aux);
static void destroy_func(struct hash_elem *elem, void *aux UNUSED);

static unsigned
hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct page_table_entry *pte = hash_entry(elem, struct page_table_entry, elem);
  return hash_bytes(&pte->upage, sizeof(pte->upage));
}
static bool
less_func(const struct hash_elem *left, const struct hash_elem *right, void *aux UNUSED)
{
  struct page_table_entry *ptel = hash_entry(left, struct page_table_entry, elem);
  struct page_table_entry *pter = hash_entry(right, struct page_table_entry, elem);
  return ptel->upage < pter->upage;
}

static void
destroy_func(struct hash_elem *elem, void *aux UNUSED)
{
  struct page_table_entry *pte = hash_entry(elem, struct page_table_entry, elem);

  if (pte->swap_slot == EMPTY_SWAP_SLOT) {
    swap_free(pte->swap_slot);
  }

  free(pte);
}

void
page_table_remove(struct hash *page_table, struct page_table_entry *pte)
{
  hash_delete(page_table, &pte->elem);
  free(pte);
}

struct hash*
page_table_init(struct hash *page_table)
{
  hash_init(page_table, hash_func, less_func, NULL);
  return page_table;
}

void
page_table_destroy(struct hash *page_table)
{
  hash_destroy(page_table, destroy_func);
}

struct page_table_entry*
page_table_append(struct hash *page_table, void *upage)
{
  struct page_table_entry *pte = malloc(sizeof(struct page_table_entry));
  pte->upage = upage;
  pte->swap_slot = EMPTY_SWAP_SLOT;
  struct hash_elem *old = hash_insert(page_table, &pte->elem);
  if (old != NULL) {
    free(pte);
    return hash_entry(old, struct page_table_entry, elem);
  }
  return pte;
}

struct page_table_entry*
page_table_find(struct hash* page_table, void *upage)
{
  struct page_table_entry pte_query;
  struct hash_elem *elem;
  pte_query.upage = upage;
  elem = hash_find(page_table, &pte_query.elem);
  if (elem == NULL) return NULL;
  return hash_entry(elem, struct page_table_entry, elem);
}
