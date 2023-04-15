#include "userprog/syscall.h"
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>

static void syscall_handler (struct intr_frame *);
static void syscall_hall (struct intr_frame *);
static void syscall_exit (struct intr_frame *);
static void syscall_write (struct intr_frame *);
static void syscall_wait (struct intr_frame *);
static void syscall_exec (struct intr_frame *);

static int get_user (const uint8_t *);
static bool put_user (uint8_t *, uint8_t);

static void *check_read_user_ptr (const void *, size_t);
static void *check_write_user_ptr (void *, size_t);
static char *check_read_user_str (const char *);

static void terminate_process (void);

static size_t ptr_size = sizeof (void *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int syscall_type = *(int *)check_read_user_ptr (f->esp, sizeof (int));
  // printf ("syscall _handle:%d", syscall_type);
  switch (syscall_type)
    {
    case SYS_HALT:
      syscall_hall (f);
      break;
    case SYS_EXIT:
      syscall_exit (f);
      break;
    case SYS_EXEC:
      syscall_exec (f);
      break;
    case SYS_WAIT:
      syscall_wait (f);
      break;
    case SYS_WRITE:
      syscall_write (f);
      break;
    }
}

static void
syscall_hall (struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
}

static void
syscall_exit (struct intr_frame *f UNUSED)
{
  int exit_code
      = *(int *)check_read_user_ptr (f->esp + ptr_size, sizeof (int));
  thread_current ()->exit_status = exit_code;
  thread_exit ();
}

static void
syscall_write (struct intr_frame *f UNUSED)
{
  int fd = *(int *)(f->esp + ptr_size);
  char *buf = *(char **)(f->esp + 2 * ptr_size);
  int size = *(int *)(f->esp + 3 * ptr_size);

  if (fd == STDOUT_FILENO)
    {
      putbuf (buf, size);
      f->eax = size;
    }
}

static void
syscall_wait (struct intr_frame *f UNUSED)
{
  int pid = *(int *)check_read_user_ptr (f->esp + ptr_size, sizeof (int));
  f->eax = process_wait (pid);
}

static void
syscall_exec (struct intr_frame *f UNUSED)
{
  char *cmd = *(char **)check_read_user_ptr (f->esp + ptr_size, ptr_size);
  check_read_user_str (cmd);
  f->eax = process_execute (cmd);
}

static void *
check_read_user_ptr (const void *ptr, size_t size)
{
  if (!is_user_vaddr (ptr))
    {
      terminate_process ();
    }

  if (get_user (ptr + size) == -1)
    {
      terminate_process ();
    }
  return (void *)ptr;
}

static void *
check_write_user_ptr (void *ptr, size_t size)
{
  if (!is_user_vaddr (ptr))
    {
      terminate_process ();
    }
  if (!put_user (ptr + size, 0))
    {
      terminate_process ();
    }
  return ptr;
}

static char *
check_read_user_str (const char *str)
{
  if (!is_user_vaddr (str))
    {
      terminate_process ();
    }
  uint8_t *_str = (uint8_t *)str;

  while (true)
    {
      int c = get_user (_str);
      if (c == -1)
        {
          terminate_process ();
        }
      else if (c == '\0')
        {
          return (char *)str;
        }
      ++_str;
    }

  NOT_REACHED ();
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}

static void
terminate_process ()
{
  thread_current ()->exit_status = -1;
  thread_exit ();
  NOT_REACHED ();
}