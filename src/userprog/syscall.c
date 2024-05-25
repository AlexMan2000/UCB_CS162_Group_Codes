#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "lib/kernel/console.h"
#include <stdbool.h>

static void syscall_handler(struct intr_frame*);
bool validate_pointer(void* addr, size_t pointer_width);
bool validate_string(const char* start_str);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }



static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  /* 
    From test sc-boundary3, what if a malicious user program doesn't 
    follow the 80x86 calling convention and move some invalid value
    to the %esp register such that esp is pointing to an invalid address.
    So we have to check the pointer first.
  */
  if (!validate_pointer(args, sizeof(uint32_t))) {
    f -> eax = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();
  }


  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */
  // printf("System call number: %d\n", args[0]); 


  switch(args[0]) {
    case SYS_EXIT:
      // Return value should be put here
      int return_code;
      if (args[1] < 0) {
        return_code = -1;
      } else {
        return_code = args[1];
      }
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, return_code);
      f->eax = return_code;
      process_exit();
      break;
    case SYS_PRACTICE:
      f -> eax = args[1] + 1;
      break;
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXEC:
      // Here exec will pass in a pointer const char* cmd_line

      /*
        As part of a system call, the kernel must often access memory through pointers provided by a user program. 
        The kernel must be very careful about doing so, because the user can pass a null pointer, a pointer
         to unmapped virtual memory, or a pointer to kernel virtual address space (above PHYS_BASE).
      */


      // We need to validate the boundary of the string passed in from the user
      bool valid = validate_string(args[1]);

      if (valid) {
        f -> eax = process_execute(args[1]);
      } else {
        f -> eax = -1;
      }

      break;
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;
    case SYS_WRITE:
      /* After this syscall, the argument passing tests should all pass */
      int fd = args[1];
      const char* srcbuf = args[2];
      int bytes_to_write = args[3];

      // If write to the stdout
      if (fd == 1) {
        // This putbuf function will make sure to write all the bytes in the 
        // srcbuf be flushed to the stdout atomically ton avoid race conditions.
        putbuf(srcbuf, bytes_to_write);
        f -> eax = bytes_to_write;
      }

      // If write to normal file

      break;
  }
}


/*
  Verify the validity of a user-provided pointer, 
  then dereference it. If you choose this route, 
  you’ll want to look at the functions in userprog/pagedir.c and in threads/vaddr.h.
   This is the simplest way to handle user memory access.
*/
bool validate_pointer(void* start_addr, size_t pointer_width) {
  void * pagedir = thread_current() -> pcb -> pagedir;
  if (pagedir == NULL) {
    return false;
  }
  
  // Check the end of the string
  if (!is_user_vaddr(start_addr)
  || pagedir_get_page(pagedir, (void *) start_addr) == NULL) {
    return false;
  }

  // Check the end of the string
  void* end_addr = start_addr + pointer_width;
  if (!is_user_vaddr(end_addr)
  || pagedir_get_page(pagedir, (void *) end_addr) == NULL) {
    return false;
  }

  return true;

}

bool validate_string(const char* start_str) {
  void * pagedir = thread_current() -> pcb -> pagedir;
  if (pagedir == NULL) {
    return false;
  }

  // Check the end of the string
  if (!is_user_vaddr(start_str)
  || pagedir_get_page(pagedir, (void *) start_str) == NULL) {
    return false;
  }

  // Check the end of the string
  char * end_str = start_str + strlen(start_str) + 1;
  
  if (!is_user_vaddr(end_str)
  || pagedir_get_page(pagedir, (void *) end_str) == NULL) {
    return false;
  }

  return true;
}

// void validate_string(const char* string_starting_addr) {
//   if (!validate)
// }