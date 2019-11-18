#ifndef PINTOS_PAGE_H
#define PINTOS_PAGE_H
#include "lib/kernel/hash.h"
#include "filesys/filesys.h"

enum page_state {
  PAGE_EMPTY,
  PAGE_SWAP,
  PAGE_FILE,
};

struct page_table_entry {
  enum page_state state;
  void *upage;
  struct hash_elem elem;
  size_t swap_slot;
  struct file *file;
  off_t file_ofs;
  uint32_t file_read_bytes;
  uint32_t file_zero_bytes;
  bool file_writable;
  struct list_elem md_elem;
  bool swap_dirty;
};

struct hash* page_table_init(struct hash *page_table);
void page_table_destroy(struct hash *page_table);
struct page_table_entry* page_table_append(struct hash *page_table, void *upage);
struct page_table_entry* page_table_find(struct hash* page_table, void *upage);
void page_table_remove(struct hash *page_table, struct page_table_entry *pte);
void page_file_map(struct page_table_entry *pte, struct file *file, off_t file_ofs, uint32_t file_read_bytes, uint32_t file_zero_bytes, bool file_writable);
void page_file_unmap(struct page_table_entry *pte);
void page_file_load(struct page_table_entry *pte, void *buffer);

#endif //PINTOS_PAGE_H
