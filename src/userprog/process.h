#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdbool.h>
#include "lib/kernel/list.h"
#include "threads/synch.h"

int process_execute (const char *file_name);
int process_wait (int);
void process_exit (void);
void process_activate (void);

struct cmd
{
  char* name;
  const char** argvs;
  int argc;
};

struct process_control_block
{
  int exit_status;
  bool waiting;
  bool exited;
  int tid;
  struct list_elem elem;
  struct lock lock;
  struct semaphore sema;
};

bool cmd_init (struct cmd *cmd, const char *cmd_line);
void free_cmd (struct cmd *cmd);
bool install_page (void *upage, void *kpage, bool writable);
struct process_control_block* create_pcb(int tid);

#endif /* userprog/process.h */
