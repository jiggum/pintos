#include <stddef.h>
#include "devices/block.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "vm/swap.h"

static struct block *swap_block;
static unsigned long swap_slot_num;
static struct bitmap *swap_slot_usage; // 1 is used 0 is free
size_t SECTOR_NUM_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;

static void swap_slot_write(const void *buffer, size_t swap_slot);
static void swap_slot_read(void *buffer, size_t swap_slot);

struct lock swap_lock;

void
swap_init(void)
{
  swap_block = block_get_role(BLOCK_SWAP);
  ASSERT(swap_block != NULL);
  swap_slot_num = block_size(swap_block) / SECTOR_NUM_PER_PAGE;
  swap_slot_usage = bitmap_create(swap_slot_num);
  bitmap_set_all(swap_slot_usage, false);
  lock_init(&swap_lock);
}

size_t
swap_out(void *buffer)
{
  lock_acquire(&swap_lock);
  size_t swap_slot = bitmap_scan(swap_slot_usage, 0, 1, false);
  ASSERT(!bitmap_test(swap_slot_usage, swap_slot));
  swap_slot_write(buffer, swap_slot);
  bitmap_set(swap_slot_usage, swap_slot, true);
  lock_release(&swap_lock);
  return swap_slot;
}

void
swap_in(void *buffer, size_t swap_slot)
{
  lock_acquire(&swap_lock);
  ASSERT(bitmap_test(swap_slot_usage, swap_slot));
  swap_slot_read(buffer, swap_slot);
  bitmap_set(swap_slot_usage, swap_slot, false);
  lock_release(&swap_lock);
}

void
swap_free(size_t swap_slot)
{
  bitmap_set(swap_slot_usage, swap_slot, false);
}

static void
swap_slot_write(const void *buffer, size_t swap_slot)
{
  size_t i;
  const void *buffer_sector;
  block_sector_t sector;
  for(i = 0; i < SECTOR_NUM_PER_PAGE; i += 1) {
    sector = (swap_slot * SECTOR_NUM_PER_PAGE) + i;
    buffer_sector = buffer + (BLOCK_SECTOR_SIZE * i);
    block_write(swap_block, sector, buffer_sector);
  }
}

static void
swap_slot_read(void *buffer, size_t swap_slot)
{
  size_t i;
  void *buffer_sector;
  block_sector_t sector;
  for(i = 0; i < SECTOR_NUM_PER_PAGE; i += 1) {
    sector = (swap_slot * SECTOR_NUM_PER_PAGE) + i;
    buffer_sector = buffer + (BLOCK_SECTOR_SIZE * i);
    block_read(swap_block, sector, buffer_sector);
  }
}