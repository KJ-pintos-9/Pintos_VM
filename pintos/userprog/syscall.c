//#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "vm/vm.h" // mmap(), munmap() 때문에 추가
#include <round.h> // mmap() 때문에 추가 - ROUND_UP
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"  // fork() 때문에 추가

#include "userprog/syscall.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
static int64_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

static struct lock filesys_lock;

/* 시스템 콜.
 *
 * 이전에는 시스템 콜 서비스가 인터럽트 핸들러에 의해 처리되었습니다
 * (예: 리눅스의 int 0x80). 하지만 x86-64에서는 제조사가 시스템 콜을
 * 요청하는 효율적인 경로인 `syscall` 명령어를 제공합니다.
 *
 * syscall 명령어는 모델 특정 레지스터(MSR)에서 값을 읽어서 작동합니다.
 * 자세한 내용은 매뉴얼을 참조하세요. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t) SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t) SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

    /* 인터럽트 서비스 루틴은 syscall_entry가 사용자 스택을 커널 모드
     * 스택으로 교체할 때까지 어떤 인터럽트도 처리하지 않아야 합니다.
     * 따라서 FLAG_FL을 마스크했습니다. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&filesys_lock);
}

void halt()
{
    power_off();
}

void exit(int status)
{
    struct thread *t = thread_current();
    // t->is_waited = false;
    // t->is_exited = true;
    t->exit_status = status;
    // t->parent_process->exit_status = status;

    thread_exit();

    // if ((t->pml4) != NULL)
    // 	printf("%s: exit(%d)\n", t->name, t->exit_status);
}

// ------- fork 이전 버전 -> 나중에 정리할 때 쓰시오 ----------

// tid_t fork (const char *thread_name) {
// 	struct list_elem *p;
// 	struct thread *t = thread_current();

// 	tid_t child_tid = process_fork(thread_name, &t->tf);

// 	if (child_tid == TID_ERROR)
// 		exit(-1);

// 	p = list_begin(&t->child_list);

// 	while ( p != list_end(&t->child_list) ) {
// 		struct list_elem *next = list_next(p);
// 		struct thread *child_thread = list_entry(p, struct thread,
// child_elem);

// 		if (child_thread->tid == child_tid) {
// 			sema_down(&child_thread->fork_sema);
// 			return child_tid;
// 		}

// 		p = next;
// 	}

// 	// if (t->parent_process->tid != 1) // 솔직히 이건 진짜 땜질인듯 (자식
// 프로세스가 fork하는거 무효화)
// 	// 	return 0; // 이 부분을 대체하는 것이 __do_fork에 있는 R.rax =
// 0이다

// 	return child_tid;

// }

tid_t fork(const char *thread_name, struct intr_frame *f)
{
    return process_fork(thread_name, f);
}

int exec(const char *cmd_line)
{
    struct thread *t = thread_current();

    //if (cmd_line == NULL) exit(-1);

    //if (pml4_get_page(t->pml4, cmd_line) == NULL) exit(-1);
	//if (spt_find_page(&t->spt, cmd_line) == NULL) exit(-1);

    check_address(cmd_line);

    char *cmd_line_copy = palloc_get_page(
        0);  // cmd_line 그냥넣으면 로드할 때 그 주소로 액세스 불가능해서 터짐
    strlcpy(cmd_line_copy, cmd_line, PGSIZE);

    if (process_exec(cmd_line_copy) == -1) exit(-1);
}

int wait(tid_t pid)
{
    return process_wait(pid);
}

bool create(const char *file, unsigned initial_size)
{
    struct thread *t = thread_current();

    //if (file == NULL) exit(-1);

    //if (pml4_get_page(t->pml4, file) == NULL) exit(-1);
	//if (spt_find_page(&t->spt, file) == NULL) exit(-1);

    check_address(file);

    if (strlen(file) == 0) return false;

    return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
    struct thread *t = thread_current();

    //if (file == NULL) exit(-1);

    //if (pml4_get_page(t->pml4, file) == NULL) exit(-1);
		//if (spt_find_page(&t->spt, file) == NULL) exit(-1);

    check_address(file);

    return filesys_remove(file);
}

int open(const char *file)
{
    struct thread *t = thread_current();
    int fd = 0;

    //if (file == NULL) exit(-1);

    //if (pml4_get_page(t->pml4, file) == NULL) exit(-1);
	//if (spt_find_page(&t->spt, file) == NULL) exit(-1);

    check_address(file);

    if (strlen(file) == 0) return -1;

    struct file *opened_file = filesys_open(file);

    if (opened_file == NULL) return -1;

    // fd = t->next_fd++;
    while (t->fdt[fd] != NULL)
    {
        fd++;
    }

    t->fdt[fd] = malloc(sizeof(struct fdt_entry));
    t->fdt[fd]->type = FILE;
    t->fdt[fd]->entry = opened_file;

    return fd;
}

int filesize(int fd)
{
    struct thread *t = thread_current();

    if (fd < 3 || fd > 127 || t->fdt[fd] == NULL) return -1;

    return file_length(t->fdt[fd]->entry);
}

void close(int fd)
{
    struct thread *t = thread_current();

    if (fd < 0 || fd > 127) exit(-1);

    if (t->fdt[fd] == NULL) return -1;

    file_close(t->fdt[fd]->entry);
    free(t->fdt[fd]);
    t->fdt[fd] = NULL;
}

int read(int fd, const void *buffer, unsigned length)
{
    struct thread *t = thread_current();
    struct file *read_file;
    struct page *page;

    check_address(buffer);

    if (page = spt_find_page(&t->spt, buffer)) {
        if (!page->writable)
            exit(-1);
    }

    if (fd < 0 || fd > 127 || length == 0) return 0;

    if (fd == 0) return input_getc();

    //if (pml4_get_page(t->pml4, buffer) == NULL) exit(-1);
	//if (spt_find_page(&t->spt, buffer) == NULL) exit(-1);

    if (fd > 2)
    {
        if (t->fdt[fd] == NULL) return 0;
        read_file = t->fdt[fd]->entry;
        return file_read(read_file, buffer, length);
    }
}

int write(int fd, const void *buffer, unsigned length)
{
    struct thread *t = thread_current();
    struct file *write_file;
    struct page *page;

    check_address(buffer);

    // if (page = spt_find_page(&t->spt, buffer)) {
    //     if (!page->writable)
    //         exit(-1);
    // }

    if (fd <= 0 || fd > 127 || length == 0) return 0;

    if (fd == 1)
    {
        /// TODO: 표준 출력 (콘솔).
        // return 읽은 바이트 수
        putbuf((char *) buffer, length);
        return length;
    }

    //if (pml4_get_page(t->pml4, buffer) == NULL) exit(-1);
	//if (spt_find_page(&t->spt, buffer) == NULL) exit(-1);

    if (fd > 2)
    {
        if (t->fdt[fd] == NULL) return 0;
        write_file = t->fdt[fd]->entry;
        return file_write(write_file, buffer, length);
    }
}

void seek(int fd, unsigned position)
{
    struct thread *t = thread_current();

    if (t->fdt[fd]->entry == NULL) return 0;

    struct file *opened_file = t->fdt[fd]->entry;

    file_seek(opened_file, (off_t) position);
}

unsigned tell(int fd)
{
    struct thread *t = thread_current();

    if (t->fdt[fd]->entry == NULL) return 0;

    struct file *opened_file = t->fdt[fd]->entry;

    return file_tell(opened_file);
}

void *mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
  struct thread *t = thread_current();

  if (addr == 0 || is_kernel_vaddr(addr) || length == 0 || fd < 0 || fd > 127 || offset % PGSIZE || t->fdt[fd]->entry == NULL) return NULL;

	if (pg_ofs(addr) != 0)
		return NULL;

	struct file *opened_file = file_reopen(t->fdt[fd]->entry);
	void *initial_addr = addr;

	uint32_t read_bytes = length < file_length(opened_file) ? length : file_length(opened_file);
	uint32_t zero_bytes = ROUND_UP(length, PGSIZE) - read_bytes;
	
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		if (is_kernel_vaddr(addr) || spt_find_page(&t->spt, addr)) { // 연속된 가상주소에 이미 매핑되어있을경우 실패, addr가 커널주소 이상으로 올라갈경우 실패
			return NULL;
		}

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct mmap_page_info *aux = malloc(sizeof(struct mmap_page_info));

		if (aux == NULL)
		{
			return NULL;
		}

		aux->file = opened_file;
		aux->offset = offset;
		aux->bytes_read = page_read_bytes;
		aux->zero_bytes = page_zero_bytes;
		aux->is_mmap_called = false;
		aux->mmaped_pages_count = 0;

		if (addr == initial_addr) {
			aux->is_mmap_called = true;
			aux->mmaped_pages_count = ROUND_UP(length, PGSIZE) / PGSIZE;
		}

		if (page_read_bytes)
		{
			if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, do_mmap, aux))
				return NULL;
		}
		else
		{
			if (!vm_alloc_page_with_initializer(VM_ANON, addr, writable, do_mmap, aux))
				return NULL;
		}

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}	

	return initial_addr;
}

void munmap(void *addr)
{
    do_munmap(addr);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
    // TODO: Your implementation goes here.
    // printf ("system call!\n");
    uint64_t sys_num = f->R.rax;  // 시스템 콜 번호 가져오기
    char *file;
    int fd;
    /* f에서 전달 받은 argument들을 가져온다. */
    switch (sys_num)
    {
        case SYS_HALT:
            /// TODO: halt() code 시스템 종료: [2, 4]
            halt();
            break;
        case SYS_EXIT:
            /// TODO: exit() code 에러: [2, 9]
            int status = (int) f->R.rdi;  // 인자 가져오기
            exit(status);
            break;
        case SYS_FORK:
            char *thread_name = (char *) f->R.rdi;
            f->R.rax = fork(thread_name, f);
            break;
        case SYS_EXEC:
            char *cmd_line = (char *) f->R.rdi;
            exec(cmd_line);
            break;
        case SYS_WAIT:
            tid_t pid = (tid_t) f->R.rdi;
            f->R.rax = wait(pid);
            break;
        case SYS_CREATE:
            file = (char *) f->R.rdi;
            unsigned initial_size = (unsigned) f->R.rsi;
            f->R.rax = create(file, initial_size);
            break;
        case SYS_REMOVE:
            file = (char *) f->R.rdi;
            f->R.rax = remove(file);
            break;
        case SYS_OPEN:
            file = (char *) f->R.rdi;
            f->R.rax = open(file);
            break;
        case SYS_FILESIZE:
            fd = (char *) f->R.rdi;
            f->R.rax = filesize(fd);
            break;
        case SYS_CLOSE:
            fd = f->R.rdi;
            close(fd);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell(f->R.rdi);
            break;
        case SYS_MMAP:
            f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
            break;
        case SYS_MUNMAP:
            munmap(f->R.rdi);
            break;
        default:
            thread_exit();
    }

    // thread_exit ();
}

void check_address(void *addr) {
    struct thread *t = thread_current();
    struct page *page;

    if (addr == NULL || is_kernel_vaddr(addr))
        exit(-1);
    if (get_user(addr) == -1)
        exit(-1);
    // if (page = spt_find_page(&t->spt, addr)) {
    //     if (!page->writable)
    //         exit(-1);
    // }

}

/* 사용자 가상 주소 UADDR에서 바이트를 읽습니다.
 * UADDR은 반드시 KERN_BASE보다 작아야 합니다.
 * 성공 시 해당 바이트 값을 반환하고, 세그멘테이션 폴트가 발생하면 -1을 반환합니다. */
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* BYTE 값을 사용자 주소 UDST에 씁니다.
 * UDST는 반드시 KERN_BASE보다 작아야 합니다.
 * 성공하면 true, 세그멘테이션 폴트 발생 시 false 반환 */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile (
    "movabsq $done_put, %0\n"
    "movb %b2, %1\n"
    "done_put:\n"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}
