#ifndef PINTOS_SWAP_H
#include <stddef.h>
#include "vm/page.h"
#define PINTOS_SWAP_H

void swap_init(void);
void swap_out(struct page_table_entry *pte, void *buffer, uint32_t *pd);
void swap_in(struct page_table_entry *pte, void *buffer, uint32_t *pd);
void swap_free(struct page_table_entry *pte);

#endif //PINTOS_SWAP_H
