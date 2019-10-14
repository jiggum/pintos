cmake_minimum_required(VERSION 3.14)
project(pintos)

include_directories (.)
include_directories (devices)
include_directories (examples)
include_directories (filesys)
include_directories (lib)
include_directories (lib/kernel)
include_directories (lib/user)
include_directories (misc)
include_directories (threads)
include_directories (userprog)
include_directories (utils)
include_directories (vm)

set(
    SOURCE_FILES
        threads/thread.c
        threads/synch.c
        threads/interrupt.c
        threads/palloc.c
        threads/malloc.c
        threads/init.c
        userprog/exception.c
        userprog/gdt.c
        userprog/pagedir.c
        userprog/process.c
        userprog/syscall.c
        userprog/tss.c
        devices/timer.c
        lib/kernel/list.c
        filesys/file.c
)

add_executable(pintos ${SOURCE_FILES})
