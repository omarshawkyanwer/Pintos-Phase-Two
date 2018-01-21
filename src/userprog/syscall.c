#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

// Added includes
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "lib/syscall-nr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "lib/string.h"
#include <stdlib.h>
#include <list.h>
#include "devices/input.h"

// Added typedefs
typedef int pid_t;

// Added variables
const int EXIT_ERR = -1;
struct lock filesys_lock;

// Added structs
struct open_file {
	int fd;
	struct file *f;
    struct list_elem elem;
};

// Added functions
static void validate_user_address (void * vaddr);

static void halt (void);
static pid_t exec (const char *cmd_line);

static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
static int wait(pid_t pid);

struct file * get_file(int fd);

static void syscall_handler (struct intr_frame *f);

void
syscall_init (void) 
{
	lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  /*
  printf ("system call!\n");
  thread_exit ();
  */

	validate_user_address(f->esp);

	uint32_t * sp = f->esp;
	int system_call_number = *sp;
	switch(system_call_number){
		case SYS_HALT:
		halt();
		break;

		case SYS_EXIT:
		validate_user_address(f->esp + 4);
		exit(*(sp + 1));
		break;

		case SYS_EXEC:
		validate_user_address(f->esp + 4);
		f->eax = exec(*(sp + 1));
		break;

		case SYS_WAIT:
        validate_user_address(f->esp + 4);
        f->eax = wait(*(sp + 1));
		break;

		case SYS_CREATE:
		validate_user_address(f->esp + 4);
		validate_user_address(f->esp + 8);
		f->eax = create(*(sp + 1), *(sp + 2));
		break;

		case SYS_REMOVE:
		validate_user_address(f->esp + 4);
		f->eax = remove(*(sp + 1));
		break;

		case SYS_OPEN:
		validate_user_address(f->esp + 4);
		f->eax = open(*(sp + 1));
		break;

		case SYS_FILESIZE:
		validate_user_address(f->esp + 4);
		f->eax = filesize(*(sp + 1));
		break;

		case SYS_READ:
		validate_user_address(f->esp + 4);
		validate_user_address(f->esp + 8);
		validate_user_address(f->esp + 12);
		f->eax = read(*(sp + 1), *(sp + 2), *(sp + 3));
		break;

		case SYS_WRITE:
		validate_user_address(f->esp + 4);
		validate_user_address(f->esp + 8);
		validate_user_address(f->esp + 12);
		f->eax = write(*(sp + 1), *(sp + 2), *(sp + 3));
		break;

		case SYS_SEEK:
		validate_user_address(f->esp + 4);
		validate_user_address(f->esp + 8);
		seek(*(sp + 1), *(sp + 2));
		break;

		case SYS_TELL:
		validate_user_address(f->esp + 4);
		f->eax = tell(*(sp + 1));
		break;

		case SYS_CLOSE:
		validate_user_address(f->esp + 4);
		close(*(sp + 1));
		break;

		default:
		printf("Unrecognized system call number: %d.", system_call_number);
	}
}

static pid_t exec (const char *cmd_line){
	validate_user_address(cmd_line);
	return process_execute(cmd_line);
}
 
static void validate_user_address(void * vaddr){
	if(vaddr == NULL || !is_user_vaddr(vaddr) || vaddr < 0)
		exit(EXIT_ERR);

	if(pagedir_get_page(thread_current()->pagedir, vaddr) == NULL)
		exit(EXIT_ERR);
}

void exit(int status){
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
	// Release resources.
	while(!list_empty(&(thread_current()->open_files))){
		struct list_elem *e = list_front(&(thread_current()->open_files));
		int fd = list_entry(e, struct open_file, elem)->fd;
		close(fd);
	}
	// locks ?
	thread_exit();
}

static void halt (void){
	shutdown_power_off();
}

static bool create (const char *file, unsigned initial_size){
	validate_user_address(file);
	lock_acquire(&filesys_lock);
	bool ret = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return ret;
}

static bool remove (const char *file){
	validate_user_address(file);
	lock_acquire(&filesys_lock);
	bool ret = filesys_remove(file);
	lock_release(&filesys_lock);
	return ret;
}

static int wait(pid_t pid) {
    return process_wait(pid);
}

static int open (const char *file){
	validate_user_address(file);
	lock_acquire(&filesys_lock);
	int fd = -1;
	struct file *f = filesys_open(file);
	if(f != NULL){
		struct open_file *of = (struct open_file *) malloc(sizeof (struct open_file));
		of->f = f;
		of->fd = fd = ++thread_current()->max_fd_used;
		list_push_back(&(thread_current()->open_files) , &(of->elem));
	}
	lock_release(&filesys_lock);
	//printf("Opened: %d\n", fd);
	return fd;
}

static int filesize (int fd){
	lock_acquire(&filesys_lock);
	struct file *f = get_file(fd);
	int ret = f == NULL ? 0 : file_length(f);
	lock_release(&filesys_lock);
	return ret;
}

static int read (int fd, void *buffer, unsigned size){
	validate_user_address(buffer);
	validate_user_address(buffer + size - 1);
	lock_acquire(&filesys_lock);
	int ret;
	if(fd == 0){
		// Read from keyboard with input_getc()
		unsigned i;
		for(i = 0; i < size; ++i)
			*(char *)(buffer + i) = input_getc();
		ret = size;
	}
	else{
		struct file *f = get_file(fd);
		ret = f == NULL ? -1 : file_read(f, buffer, size);
	}
	lock_release(&filesys_lock);
	return ret;
}

static int write (int fd, const void *buffer, unsigned size){
	validate_user_address(buffer);
	validate_user_address(buffer + size - 1);
	lock_acquire(&filesys_lock);
	int ret;
	if(fd == 1){
		// Write to console with putbuf
		putbuf (buffer, size);
		ret = size;
	}
	else{
		struct file *f = get_file(fd);
		if(f == NULL){
			lock_release(&filesys_lock);
			//printf("Didn't find: %d\n", fd);
			exit(EXIT_ERR);
		}
		ret = file_write(f, buffer, size);
	}
	lock_release(&filesys_lock);
	return ret;
}

static void seek (int fd, unsigned position){
	lock_acquire(&filesys_lock);
	struct file *f = get_file(fd);
	if(f == NULL){
		lock_release(&filesys_lock);
		return;
	}
	file_seek (f, position);
	lock_release(&filesys_lock);
}

static unsigned tell (int fd){
	lock_acquire(&filesys_lock);
	struct file *f = get_file(fd);
	if(f == NULL){
		lock_release(&filesys_lock);
		return 0;
	}
	int ret = file_tell (f);
	lock_release(&filesys_lock);
	return ret;
}

static void close (int fd){
	lock_acquire(&filesys_lock);
	struct file *f = get_file(fd);
	if(f == NULL){
		lock_release(&filesys_lock);
		return;
	}
	file_close (f);
	struct list_elem *e = list_begin (&(thread_current()->open_files));
    for (; e != list_end (&(thread_current()->open_files)); e = list_next (e))
    {
        struct open_file *of = list_entry (e, struct open_file, elem);
        if(of->fd == fd){
        	list_remove (&(of->elem));
        	break;
        }        
    }
	lock_release(&filesys_lock);
	//printf("Closed: %d\n", fd);
}

// Returns the file with the given fd if found, null otherwise.
struct file * get_file(int fd){
	struct list_elem *e = list_begin (&(thread_current()->open_files));
    for (; e != list_end (&(thread_current()->open_files)); e = list_next (e))
    {
        struct open_file *of = list_entry (e, struct open_file, elem);
        if(of->fd == fd) return of->f;
    }
    return NULL;
}
