#ifndef PINTOS_SWAP_H
#include <stddef.h>
#define EMPTY_SWAP_SLOT -1
#define PINTOS_SWAP_H

#endif //PINTOS_SWAP_H

void swap_init(void);
size_t swap_out(void *buffer);
void swap_in(void *buffer, size_t swap_slot);
void swap_free(size_t swap_slot);
