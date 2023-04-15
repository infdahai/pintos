#include "userprog/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>

static void syscall_handler (struct intr_frame *);
static void syscall_hall (struct intr_frame *);
static void syscall_exit (struct intr_frame *);
static void syscall_wait (struct intr_frame *);
static void syscall_exec (struct intr_frame *);
static void syscall_create (struct intr_frame *);
static void syscall_remove (struct intr_frame *);
static void syscall_open (struct intr_frame *);
static void syscall_filesize (struct intr_frame *);
static void syscall_read (struct intr_frame *);
static void syscall_write (struct intr_frame *);
static void syscall_seek (struct intr_frame *);
static void syscall_tell (struct intr_frame *);
static void syscall_close (struct intr_frame *);

static int get_user (const uint8_t *);
static bool put_user (uint8_t *, uint8_t);
static struct file_entry *get_file (int);

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
    case SYS_CREATE:
      syscall_create (f);
      break;
    case SYS_REMOVE:
      syscall_remove (f);
      break;
    case SYS_OPEN:
      syscall_open (f);
      break;
    case SYS_FILESIZE:
      syscall_filesize (f);
      break;
    case SYS_READ:
      syscall_read (f);
      break;
    case SYS_WRITE:
      syscall_write (f);
      break;
    case SYS_SEEK:
      syscall_seek (f);
      break;
    case SYS_TELL:
      syscall_tell (f);
      break;
    case SYS_CLOSE:
      syscall_close (f);
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

/*
 * bool create (const char *file, unsigned initial_size)
 */
static void
syscall_create (struct intr_frame *f UNUSED)
{
  char *file = *(char **)check_read_user_ptr (f->esp + ptr_size, ptr_size);
  check_read_user_str (file);
  unsigned initial_size = *(unsigned *)check_read_user_ptr (
      f->esp + 2 * ptr_size, sizeof (unsigned));

  lock_acquire (&filesys_lock);
  f->eax = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
}

/*
 * bool remove (const char *file)
 */
static void
syscall_remove (struct intr_frame *f UNUSED)
{
  char *file = *(char **)check_read_user_ptr (f->esp + ptr_size, ptr_size);
  check_read_user_str (file);

  lock_acquire (&filesys_lock);
  f->eax = filesys_remove (file);
  lock_release (&filesys_lock);
}

/*
 * int open (const char *file)
 */
static void
syscall_open (struct intr_frame *f UNUSED)
{
  char *file = *(char **)check_read_user_ptr (f->esp + ptr_size, ptr_size);
  check_read_user_str (file);

  lock_acquire (&filesys_lock);
  struct file *open_file = filesys_open (file);
  lock_release (&filesys_lock);

  if (open_file == NULL)
    {
      f->eax = -1;
      return;
    }

  struct thread *cur = thread_current ();
  struct file_entry *entry = malloc (sizeof (struct file_entry));
  entry->fd = cur->next_fd++;
  entry->f = open_file;
  list_push_back (&cur->file_list, &entry->elem);
  f->eax = entry->fd;
}

/*
 * int filesize (int fd)
 */
static void
syscall_filesize (struct intr_frame *f UNUSED)
{
  int fd = *(int *)check_read_user_ptr (f->esp + ptr_size, sizeof (int));
  struct file_entry *entry = get_file (fd);
  if (entry == NULL)
    {
      f->eax = -1;
    }
  else
    {
      lock_acquire (&filesys_lock);
      f->eax = file_length (entry->f);
      lock_release (&filesys_lock);
    }
}

/*
 * int read (int fd, void *buffer, unsigned size)
 */
static void
syscall_read (struct intr_frame *f UNUSED)
{
  int fd = *(int *)check_read_user_ptr (f->esp + ptr_size, sizeof (int));
  void *buf = *(void **)check_read_user_ptr (f->esp + 2 * ptr_size, ptr_size);
  unsigned size = *(unsigned *)check_read_user_ptr (f->esp + 3 * ptr_size,
                                                    sizeof (unsigned));
  check_write_user_ptr (buf, size);

  if (fd == 0)
    {
      for (unsigned i = 0; i < size; i++)
        {
          *(uint8_t *)buf = input_getc ();
          buf += sizeof (uint8_t);
        }
      f->eax = size;
      return;
    }
  if (fd == 1)
    {
      terminate_process ();
    }

  struct file_entry *entry = get_file (fd);
  if (entry == NULL)
    {
      f->eax = -1;
    }
  else
    {
      lock_acquire (&filesys_lock);
      f->eax = file_read (entry->f, buf, size);
      lock_release (&filesys_lock);
    }
}

/*
 * int write (int fd, const void *buffer, unsigned size)
 */
static void
syscall_write (struct intr_frame *f UNUSED)
{
  int fd = *(int *)check_read_user_ptr (f->esp + ptr_size, sizeof (int));
  void *buf = *(void **)check_read_user_ptr (f->esp + 2 * ptr_size, ptr_size);
  unsigned size = *(unsigned *)check_read_user_ptr (f->esp + 3 * ptr_size,
                                                    sizeof (unsigned));
  check_read_user_ptr (buf, size);

  if (fd == 0)
    {
      terminate_process ();
    }
  if (fd == STDOUT_FILENO)
    {
      putbuf ((const char *)buf, size);
      f->eax = size;
      return;
    }

  struct file_entry *entry = get_file (fd);
  if (entry == NULL)
    {
      f->eax = -1;
    }
  else
    {
      lock_acquire (&filesys_lock);
      f->eax = file_write (entry->f, buf, size);
      lock_release (&filesys_lock);
    }
}

/*
 * void seek (int fd, unsigned position)
 */
static void
syscall_seek (struct intr_frame *f UNUSED)
{
  int fd = *(int *)check_read_user_ptr (f->esp + ptr_size, sizeof (int));
  unsigned pos = *(unsigned *)check_read_user_ptr (f->esp + 2 * ptr_size,
                                                   sizeof (unsigned));
  struct file_entry *entry = get_file (fd);
  if (entry != NULL)
    {
      lock_acquire (&filesys_lock);
      file_seek (entry->f, pos);
      lock_release (&filesys_lock);
    }
}

/*
 * unsigned tell (int fd)
 */
static void
syscall_tell (struct intr_frame *f UNUSED)
{
  int fd = *(int *)check_read_user_ptr (f->esp + ptr_size, sizeof (int));

  struct file_entry *entry = get_file (fd);
  if (entry == NULL)
    {
      f->eax = -1;
    }
  else
    {
      lock_acquire (&filesys_lock);
      f->eax = file_tell (entry->f);
      lock_release (&filesys_lock);
    }
}

/*
 * void close (int fd)
 */
static void
syscall_close (struct intr_frame *f UNUSED)
{
  int fd = *(int *)check_read_user_ptr (f->esp + ptr_size, sizeof (int));

  struct file_entry *entry = get_file (fd);
  if (entry != NULL)
    {
      lock_acquire (&filesys_lock);
      file_close (entry->f);
      list_remove (&entry->elem);
      free (entry);
      lock_release (&filesys_lock);
    }
}

static void *
check_read_user_ptr (const void *ptr, size_t size)
{
  if (!is_user_vaddr (ptr))
    {
      terminate_process ();
    }
  if (size >= 1)
    {
      if (get_user (ptr + size - 1) == -1)
        {
          terminate_process ();
        }
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
  if (size >= 1)
    {
      if (!put_user (ptr + size - 1, 0))
        {
          terminate_process ();
        }
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

static struct file_entry *
get_file (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  for (e = list_begin (&cur->file_list); e != list_end (&cur->file_list);
       e = list_next (e))
    {
      struct file_entry *entry = list_entry (e, struct file_entry, elem);
      if (entry->fd == fd)
        {
          return entry;
        }
    }
  return NULL;
}

static void
terminate_process ()
{
  thread_current ()->exit_status = -1;
  thread_exit ();
  NOT_REACHED ();
}