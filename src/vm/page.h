#ifndef PINTOS_PAGE_H
#define PINTOS_PAGE_H
#include "lib/kernel/hash.h"
#endif //PINTOS_PAGE_H

struct page_table_entry {
  void *upage;
  struct hash_elem elem;
};

struct hash* page_table_init(struct hash *page_table);
void page_table_destory(struct hash *page_table);
bool page_table_append(struct hash *page_table, void *upage);
struct page_table_entry* page_table_find(struct hash* page_table, void *upage);
