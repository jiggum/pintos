#include <debug.h>
#include <stdio.h>
#include "vm/page.h"
#include "lib/kernel/hash.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

static unsigned hash_func(const struct hash_elem *e, void *aux);
static bool less_func(const struct hash_elem *left, const struct hash_elem *right, void *aux);
static void destroy_func(struct hash_elem *elem, void *aux UNUSED);
bool page_table_append(struct hash *page_table, void *upage);

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
  free(pte);
}

struct hash*
page_table_init(struct hash *page_table)
{
  hash_init(page_table, hash_func, less_func, NULL);
  return page_table;
}

void
page_table_destory(struct hash *page_table)
{
  hash_destroy(page_table, destroy_func);
}

bool
page_table_append(struct hash *page_table, void *upage)
{
  ASSERT (is_user_vaddr (upage));
  if(upage == NULL) return false;
  struct page_table_entry *pte = malloc(sizeof(struct page_table_entry));
  pte->upage = upage;
  struct hash_elem *old = hash_insert(page_table, &pte->elem);
  if (old != NULL) {
    free(pte);
    return false;
  }
  return true;
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
