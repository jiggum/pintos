#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */

struct cmd
  {
    char* name;
    const char** argvs;
    int argc;
  };

bool cmd_init (struct cmd *cmd, const char *cmd_line);
void free_cmd (struct cmd *cmd);
