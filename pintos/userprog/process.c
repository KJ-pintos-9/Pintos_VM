#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"
#ifdef VM
#include "vm/vm.h"
#endif

struct lazy_load_info
{
    struct file *file;    //파일 포인터
    off_t offset;         //오프셋
    uint32_t bytes_read;  //읽을 바이트 수
    uint32_t zero_bytes;  // 나머지 0으로 채울 바이트 수
};

static void process_cleanup(void);
// static bool load (const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
static void init_stack_frame(struct intr_frame *if_, char **argv,
                             int argc);  // 필요하면 직접 구현
static void copy_to_user(struct intr_frame *if_, void *argv, int size);
void aux_init(struct lazy_load_info *aux, struct file *file, off_t offset,
              uint32_t bytes_read, uint32_t zero_bytes);

// lazy_load를 위한 구조체


/* initd와 다른 프로세스를 위한 일반적인 프로세스 초기화 함수. */
static void process_init(void)
{
    struct thread *current = thread_current();
}

/* FILE_NAME에서 로드된 "initd"라는 첫 번째 사용자 프로그램을 시작합니다.
 * 새로운 스레드는 process_create_initd()가 반환되기 전에 스케줄될 수 있습니다
 * (심지어 종료될 수도 있습니다). initd의 스레드 ID를 반환하거나,
 * 스레드를 생성할 수 없으면 TID_ERROR를 반환합니다.
 * 주의: 이 함수는 한 번만 호출되어야 합니다. */
tid_t process_create_initd(const char *file_name)
{
    char *fn_copy, *tmp_ptr;
    tid_t tid;

    /* FILE_NAME의 복사본을 만듭니다.
     * 그렇지 않으면 호출자와 load() 사이에 경쟁 조건이 발생합니다. */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL) return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    /* for file_name 15자 제한 */
    strtok_r(file_name, " ", &tmp_ptr);

    /* FILE_NAME을 실행할 새로운 스레드를 생성합니다. */
    tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
    if (tid == TID_ERROR) palloc_free_page(fn_copy);
    return tid;
}

/* 첫 번째 사용자 프로세스를 실행하는 스레드 함수. */
static void initd(void *f_name)
{
#ifdef VM
    supplemental_page_table_init(&thread_current()->spt);
#endif

    process_init();

    if (process_exec(f_name) < 0)
        // PANIC("Fail to launch initd\n");
        palloc_free_page(f_name);
    exit(-1);
    NOT_REACHED();
}

/* 현재 프로세스를 `name`으로 복제합니다. 새 프로세스의 스레드 ID를 반환하거나,
 * 스레드를 생성할 수 없으면 TID_ERROR를 반환합니다. */
tid_t process_fork(const char *name, struct intr_frame *if_)
{
    /* 현재 스레드를 새 스레드로 복제합니다. */
    struct thread *t = thread_current();
    memcpy(&t->fork_if, if_, sizeof(struct intr_frame));

    tid_t child_tid = thread_create(name, PRI_DEFAULT, __do_fork, t);

    sema_down(&t->fork_sema);

    if (child_tid != TID_ERROR)
    {
        struct list_elem *p = list_begin(&t->child_list);

        while (p != list_end(&t->child_list))
        {
            struct list_elem *next = list_next(p);
            struct thread *child_thread =
                list_entry(p, struct thread, child_elem);

            if (child_thread->tid == child_tid)
            {
                // sema_down(&child_thread->fork_sema); 여기서 기다리면 여기까지
                // 오기전에 자식 스레드로의 컨텍스트 스위칭이 일어날 수 있음
                return child_tid;
            }

            p = next;
        }
    }

    return child_tid;
}

#ifndef VM
/* 이 함수를 pml4_for_each에 전달하여 부모의 주소 공간을 복제합니다.
 * 이는 프로젝트 2에서만 사용됩니다. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux)
{
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *) aux;
    void *parent_page;  // 부모의 PML4 엔트리를 순회하면서 얻은 물리주소
    void *newpage;
    bool writable;

    /* 1. TODO: parent_page가 커널 페이지라면, 즉시 반환합니다. */
    if (is_kernel_vaddr(va))
    {
        return true;
    }

    /* 2. 부모의 페이지 맵 레벨 4에서 VA를 해석합니다. */
    parent_page = pml4_get_page(parent->pml4, va);  // 처음에 있던 구문

    /* 3. TODO: 자식을 위한 새로운 PAL_USER 페이지를 할당하고 결과를
     *    TODO: NEWPAGE에 설정합니다. */
    newpage = palloc_get_page(PAL_USER | PAL_ZERO);

    /* 4. TODO: 부모의 페이지를 새 페이지로 복제하고
     *    TODO: 부모의 페이지가 쓰기 가능한지 확인합니다 (결과에 따라
     *    TODO: WRITABLE을 설정합니다). */

    memcpy(newpage, parent_page, PGSIZE);
    writable =
        is_writable(pte);  // 지금까지 가상주소에 물리주소 넣고있었던건가..?

    /* 5. WRITABLE 권한으로 주소 VA에 새 페이지를 자식의 페이지 테이블에
     * 추가합니다. */
    if (!pml4_set_page(current->pml4, va, newpage, writable))
    {  // 처음에 있던 구문
        /* 6. TODO: 페이지 삽입에 실패하면, 오류 처리를 수행합니다. */
        palloc_free_page(newpage);
        return false;
    }
    return true;
}
#endif

/* 부모의 실행 컨텍스트를 복사하는 스레드 함수.
 * 힌트) parent->tf는 프로세스의 사용자 영역 컨텍스트를 보유하지 않습니다.
 *       즉, process_fork의 두 번째 인수를 이 함수에 전달해야 합니다. */
static void __do_fork(void *aux)
{
    struct intr_frame if_;
    struct thread *parent = aux;
    struct thread *current = thread_current();
    /* TODO: 어떻게든 parent_if를 전달합니다. (즉, process_fork()의 if_) */
    struct intr_frame *parent_if = &parent->fork_if;
    bool succ = true;

    /* 1. CPU 컨텍스트를 로컬 스택에 읽습니다. */
    memcpy(&if_, parent_if, sizeof(struct intr_frame));

    /* 2. PT를 복제합니다 */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL) goto error;

    process_activate(current);

#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt)) goto error;
#else
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) goto error;
#endif

    /* TODO: 여기에 코드를 작성하세요.
     * TODO: 힌트) 파일 객체를 복제하려면 include/filesys/file.h의
     * `file_duplicate`를 사용하세요.
     * TODO:       부모는 이 함수가 부모의 자원을 성공적으로 복제할 때까지
     * TODO:       fork()에서 반환하지 않아야 합니다. */

    // for (int i = 3; parent->fdt[i] != NULL; i++) {
    // 	if ((current->fdt[i]->entry = file_duplicate(parent->fdt[i]->entry)) ==
    // NULL) 		goto error;
    // }
    for (int fd = 0; fd < 128; fd++)
    {
        if (parent->fdt[fd] != NULL && parent->fdt[fd]->type == 1)
        {  // FILE 의미가 겹쳐서 여기서만 1로 사용
            current->fdt[fd] = calloc(1, sizeof(struct fdt_entry));
            current->fdt[fd]->type = 1;
            current->fdt[fd]->entry = file_duplicate(parent->fdt[fd]->entry);
        }
    }

    // current->next_fd = parent->next_fd; // 얘 추가해줘야 fdt 상황과 next_fd가
    // 서로 맞음

    if_.R.rax = 0;

    // sema_up(&current->fork_sema);
    sema_up(&parent->fork_sema);

    process_init();

    /* 마지막으로, 새로 생성된 프로세스로 전환합니다. */
    if (succ) do_iret(&if_);
error:
    // sema_up(&current->fork_sema);
    sema_up(&parent->fork_sema);
    thread_exit();
}

/* 현재 실행 컨텍스트를 f_name으로 전환합니다.
 * 실패 시 -1을 반환합니다. */
int process_exec(void *f_name)
{
    char *file_name = f_name;
    bool success;
    int kb = 1024 * 4;

    /* 명렁어 전체 길이 제한 4KB */
    ASSERT(strlen(f_name) <= kb);

    /* 스레드 구조의 intr_frame을 사용할 수 없습니다.
     * 이는 현재 스레드가 다시 스케줄될 때,
     * 실행 정보를 멤버에 저장하기 때문입니다. */
    struct intr_frame _if;
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    /* 먼저 현재 컨텍스트를 종료합니다 */
    process_cleanup();

    /* 그리고 바이너리를 로드합니다 */
    success = load(file_name, &_if);
    // hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true);
    /* 로드가 실패하면 종료합니다. */
    palloc_free_page(file_name);

    if (!success) return -1;

    /* 전환된 프로세스를 시작합니다. */
    /* 유저 모드 진입 return 함수 */
    do_iret(&_if);

    NOT_REACHED();
}

/* 스레드 TID가 죽기를 기다리고 종료 상태를 반환합니다. 커널에 의해
 * 종료되었다면 (즉, 예외로 인해 종료됨), -1을 반환합니다. TID가 유효하지
 * 않거나 호출 프로세스의 자식이 아니거나, 주어진 TID에 대해 process_wait()가
 * 이미 성공적으로 호출되었다면, 기다리지 않고 즉시 -1을 반환합니다.
 *
 * 이 함수는 문제 2-2에서 구현될 예정입니다. 지금은 아무것도 하지 않습니다. */
// int
// process_wait (tid_t child_tid UNUSED) {

// 	/* XXX: 힌트) process_wait(initd)가 있으면 pintos가 종료되므로,
// 	 * XXX:       process_wait를 구현하기 전에 여기에 무한 루프를 추가하는
// 것을 권장합니다. */ 	thread_sleep(500);
// 	// while(1) {

// 	// }
// 	return -1;
// }

int process_wait(tid_t child_tid UNUSED)
{
    struct list_elem *p;
    struct thread *t = thread_current();

    p = list_begin(&t->child_list);

    while (p != list_end(&t->child_list))
    {
        struct list_elem *next = list_next(p);
        struct thread *child_thread = list_entry(p, struct thread, child_elem);

        if (child_thread->tid == child_tid)
        {
            if (child_thread->is_waited) return -1;

            if (!child_thread->is_exited)
            {
                child_thread->is_waited = true;
                sema_down(&child_thread->wait_sema);
                sema_up(&child_thread->exit_sema);  // 비몽사몽..
            }

            return child_thread->exit_status;
        }

        p = next;
    }

    return -1;
}

/* 현재 프로세스의 리소스를 해제합니다. */
void process_exit(void)
{
    struct thread *curr = thread_current();
    // int fd = 0;
    /* TODO: 여기에 코드를 작성하세요.
     * TODO: 프로세스 종료 메시지를 구현하세요
     * (project2/process_termination.html 참조).
     * TODO: 여기에 프로세스 리소스 정리를 구현하는 것을 권장합니다. */

    if ((curr->pml4) != NULL)
        printf("%s: exit(%d)\n", curr->name, curr->exit_status);

    // struct list_elem *p; = list_begin(&t->child_list);

    // while ( p != list_end(&t->child_list) ) {
    // 	struct list_elem *next = list_next(p);
    // 	struct thread *child_thread = list_entry(p, struct thread, child_elem);

    // 	if (child_thread != NULL) {

    // 	}

    // 	p = next;
    // }
    if (curr->exec_file != NULL)
    {
        file_close(curr->exec_file);
        curr->exec_file = NULL;
    }
    // for (fd = 0; fd < sizeof(curr->fdt)/sizeof(void *); fd++) {
    // 	if (curr->fdt[fd]->type == 1) // FILE 의미가 겹쳐서 여기서만 1로 사용
    // 		file_close(curr->fdt[fd]->entry);
    // }

    process_cleanup();
}

/* 현재 프로세스의 리소스를 해제합니다. */
static void process_cleanup(void)
{
    struct thread *curr = thread_current();

#ifdef VM
    supplemental_page_table_kill(&curr->spt);
#endif

    uint64_t *pml4;
    /* 현재 프로세스의 페이지 디렉터리를 파괴하고 커널 전용
     * 페이지 디렉터리로 다시 전환합니다. */
    pml4 = curr->pml4;
    if (pml4 != NULL)
    {
        /* 여기서 올바른 순서는 매우 중요합니다. 페이지 디렉터리를 전환하기 전에
         * cur->pagedir을 NULL로 설정해야 합니다. 그래야 타이머 인터럽트가
         * 프로세스 페이지 디렉터리로 다시 전환할 수 없습니다. 프로세스의 페이지
         * 디렉터리를 파괴하기 전에 기본 페이지 디렉터리를 활성화해야 합니다.
         * 그렇지 않으면 활성 페이지 디렉터리가 해제된(그리고 지워진) 것이
         * 됩니다. */
        curr->pml4 = NULL;
        pml4_activate(NULL);
        pml4_destroy(pml4);
    }
}

/* 다음 스레드에서 사용자 코드를 실행하기 위해 CPU를 설정합니다.
 * 이 함수는 모든 컨텍스트 스위치에서 호출됩니다. */
void process_activate(struct thread *next)
{
    /* 스레드의 페이지 테이블을 활성화합니다. */
    pml4_activate(next->pml4);

    /* 인터럽트 처리에 사용할 스레드의 커널 스택을 설정합니다. */
    tss_update(next);
}

/* ELF 바이너리를 로드합니다. 다음 정의들은 ELF 규격 [ELF1]에서
 * 거의 그대로 가져온 것입니다. */

/* ELF 타입들. [ELF1] 1-2 참조. */
#define EI_NIDENT 16

#define PT_NULL 0           /* 무시. */
#define PT_LOAD 1           /* 로드 가능한 세그먼트. */
#define PT_DYNAMIC 2        /* 동적 링킹 정보. */
#define PT_INTERP 3         /* 동적 로더 이름. */
#define PT_NOTE 4           /* 보조 정보. */
#define PT_SHLIB 5          /* 예약됨. */
#define PT_PHDR 6           /* 프로그램 헤더 테이블. */
#define PT_STACK 0x6474e551 /* 스택 세그먼트. */

#define PF_X 1 /* 실행 가능. */
#define PF_W 2 /* 쓰기 가능. */
#define PF_R 4 /* 읽기 가능. */

/* 실행 파일 헤더. [ELF1] 1-4 ~ 1-8 참조.
 * 이것은 ELF 바이너리의 맨 처음에 나타납니다. */
struct ELF64_hdr
{
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ELF64_PHDR
{
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* FILE_NAME에서 ELF 실행 파일을 현재 스레드로 로드합니다.
 * 실행 파일의 진입점을 *RIP에 저장하고
 * 초기 스택 포인터를 *RSP에 저장합니다.
 * 성공하면 true를, 그렇지 않으면 false를 반환합니다. */
bool load(const char *file_name, struct intr_frame *if_)
{
    struct thread *t = thread_current();
    struct ELF ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i, argc = 0; /* idx for argvs */
    /* 추가한 변수들 */
    char *argv[64], *token, *save_ptr;

    /* page의 사이즈 만큼 메모리 공간을 할당해주거나, 조건문을 통해 확인한다. */
    for (token = strtok_r(file_name, " ", &save_ptr); token != NULL;
         token = strtok_r(NULL, " ", &save_ptr))
        argv[argc++] = token;

    file_name = argv[0];

    /* 페이지 디렉터리를 할당하고 활성화합니다. */
    t->pml4 = pml4_create();
    if (t->pml4 == NULL) goto done;
    process_activate(thread_current());

    /* 실행 파일을 엽니다. */
    file = filesys_open(file_name);
    if (file == NULL)
    {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    /* 실행 파일 헤더를 읽고 검증합니다. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
        ehdr.e_machine != 0x3E  // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) ||
        ehdr.e_phnum > 1024)
    {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* 프로그램 헤더를 읽습니다. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++)
    {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file)) goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type)
        {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* 이 세그먼트를 무시합니다. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment(&phdr, file))
                {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint64_t file_page = phdr.p_offset & ~PGMASK;
                    uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint64_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0)
                    {
                        /* 일반 세그먼트.
                         * 디스크에서 초기 부분을 읽고 나머지는 0으로 채웁니다.
                         */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes =
                            (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) -
                             read_bytes);
                    }
                    else
                    {
                        /* 완전히 0.
                         * 디스크에서 아무것도 읽지 않습니다. */
                        read_bytes = 0;
                        zero_bytes =
                            ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void *) mem_page,
                                      read_bytes, zero_bytes, writable))
                        goto done;
                }
                else
                    goto done;
                break;
        }
    }

    /* 스택을 설정합니다. */
    if (!setup_stack(if_)) goto done;

    /* 시작 주소. */
    if_->rip = ehdr.e_entry;

    /* TODO: 여기에 코드를 작성하세요.
     * TODO: 인수 전달을 구현하세요 (project2/argument_passing.html 참조). */
    /* 필요하면 함수 직접 구현 */
    if_->rsp = USER_STACK;

    init_stack_frame(if_, argv, argc);

    success = true;

done:
    /* 로드가 성공했든 실패했든 여기에 도달합니다. */
    // file_close (file); // 이거 대신에
    if (file != NULL)
    {
        t->exec_file = file;
        file_deny_write(file);
    }  // 실행중인 파일에 대한 쓰기 거부
    return success;
}

static void init_stack_frame(struct intr_frame *if_, char **argv, int argc)
{
    char *argv_address_list[64]; /* argv address list */
    int padding = 0;

    /* stack frame에 argv 값 넣기 */
    for (int i = argc - 1; i >= 0; i--)
    {
        char *a = argv[i];
        int size = strlen(a) + 1;

        if_->rsp -= size; /* 미리 argv[i]번의 길이 +1 만큼 address 뺀다 */
        copy_to_user(if_, a, size);
        // memcpy(if_->rsp, a, size); /* 미리 계산한 주소에 a를 size만큼 값을
        // 넣는다. */
        argv_address_list[i] = if_->rsp;
    }

    /* double world align */
    padding = if_->rsp % 8;
    if_->rsp -= padding;
    copy_to_user(if_, 0, padding);
    // memset(if_->rsp, 0, padding); /* 미리 계산된 if_->rsp에 0으로 padding
    // 사이즈만큼 세팅 */

    /* null 포인터 주소 */
    if_->rsp -= sizeof(char *);
    copy_to_user(if_, 0, sizeof(char *));
    // memset(if_->rsp, 0, sizeof(char *));

    /* stack frame에 argv 값 포인터 주소 넣기 */
    for (int i = argc - 1; i >= 0; i--)
    {
        if_->rsp -= sizeof(char *);
        *(char **) if_->rsp =
            argv_address_list[i]; /* if_->rsp 주소를 char 타입으로 역참조 */
    }

    /* return address */
    if_->rsp -= sizeof(void(*));
    copy_to_user(if_, 0, sizeof(void *));
    // memset(if_->rsp, 0, sizeof(void *));

    if_->R.rdi = argc;
    if_->R.rsi = if_->rsp + sizeof(void *); /* return address로부터 포인터 크기
                                               만큼 위에가 argv 위치 */
}

static void copy_to_user(struct intr_frame *if_, void *argv, int size)
{
    ASSERT(is_user_vaddr(if_->rsp));
    if (argv == 0)
        memset(if_->rsp, (int *) argv, size);
    else
        memcpy(if_->rsp, (char *) argv, size);
}

/* PHDR이 FILE에서 유효하고 로드 가능한 세그먼트를 설명하는지 확인하고,
 * 그렇다면 true를, 그렇지 않다면 false를 반환합니다. */
static bool validate_segment(const struct Phdr *phdr, struct file *file)
{
    /* p_offset과 p_vaddr은 같은 페이지 오프셋을 가져야 합니다. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false;

    /* p_offset은 FILE 내부를 가리켜야 합니다. */
    if (phdr->p_offset > (uint64_t) file_length(file)) return false;

    /* p_memsz는 최소한 p_filesz만큼 커야 합니다. */
    if (phdr->p_memsz < phdr->p_filesz) return false;

    /* 세그먼트는 비어있으면 안 됩니다. */
    if (phdr->p_memsz == 0) return false;

    /* 가상 메모리 영역은 시작과 끝이 모두 사용자 주소 공간 범위 내에 있어야
     * 합니다. */
    if (!is_user_vaddr((void *) phdr->p_vaddr)) return false;
    if (!is_user_vaddr((void *) (phdr->p_vaddr + phdr->p_memsz))) return false;

    /* 영역이 커널 가상 주소 공간을 "감쌀" 수 없습니다. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;

    /* 페이지 0 매핑을 금지합니다.
       페이지 0을 매핑하는 것은 나쁜 아이디어일 뿐만 아니라, 만약 허용한다면
       null 포인터를 시스템 콜에 전달하는 사용자 코드가 memcpy() 등의
       null 포인터 어설션을 통해 커널을 패닉시킬 가능성이 매우 높습니다. */
    if (phdr->p_vaddr < PGSIZE) return false;

    /* 문제없습니다. */
    return true;
}

#ifndef VM
/* 이 블록의 코드는 프로젝트 2에서만 사용됩니다.
 * 전체 프로젝트 2에 대한 함수를 구현하려면 #ifndef 매크로 외부에 구현하세요. */

/* load() 도우미 함수들. */
static bool install_page(void *upage, void *kpage, bool writable);

/* FILE의 오프셋 OFS에서 시작하여 주소 UPAGE로 세그먼트를 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다:
 *
 * - UPAGE의 READ_BYTES 바이트는 오프셋 OFS에서 시작하여 FILE에서 읽어야 합니다.
 *
 * - UPAGE + READ_BYTES의 ZERO_BYTES 바이트는 0으로 채워야 합니다.
 *
 * 이 함수에 의해 초기화된 페이지는 WRITABLE이 true이면 사용자 프로세스가
 * 수정할 수 있어야 하고, 그렇지 않으면 읽기 전용이어야 합니다.
 *
 * 성공하면 true를, 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를
 * 반환합니다. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable)
{
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* 이 페이지를 채우는 방법을 계산합니다.
         * FILE에서 PAGE_READ_BYTES 바이트를 읽고
         * 마지막 PAGE_ZERO_BYTES 바이트를 0으로 채웁니다. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* 메모리 페이지를 가져옵니다. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL) return false;

        /* 이 페이지를 로드합니다. */
        if (file_read(file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* 프로세스의 주소 공간에 페이지를 추가합니다. */
        if (!install_page(upage, kpage, writable))
        {
            printf("fail\n");
            palloc_free_page(kpage);
            return false;
        }

        /* 진행합니다. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* USER_STACK에 0으로 채워진 페이지를 매핑하여 최소한의 스택을 생성합니다 */
static bool setup_stack(struct intr_frame *if_)
{
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL)
    {
        success = install_page(((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page(kpage);
    }
    return success;
}

/* 사용자 가상 주소 UPAGE에서 커널 가상 주소 KPAGE로의 매핑을 페이지 테이블에
 * 추가합니다. WRITABLE이 true이면 사용자 프로세스가 페이지를 수정할 수 있고,
 * 그렇지 않으면 읽기 전용입니다.
 * UPAGE는 아직 매핑되지 않아야 합니다.
 * KPAGE는 아마도 palloc_get_page()로 사용자 풀에서 얻은 페이지여야 합니다.
 * 성공하면 true를, UPAGE가 이미 매핑되어 있거나 메모리 할당이 실패하면 false를
 * 반환합니다. */
static bool install_page(void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current();

    /* 해당 가상 주소에 이미 페이지가 없는지 확인한 다음,
     * 우리의 페이지를 거기에 매핑합니다. */
    return (pml4_get_page(t->pml4, upage) == NULL &&
            pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* 여기서부터는 프로젝트 3 이후에 사용될 코드입니다.
 * 프로젝트 2에서만 함수를 구현하려면 위의 블록에 구현하세요. */

// 첫 페이지 폴트 발생 시, 요청된 파일 내용을 메모리에 로드
static bool lazy_load_segment(struct page *page, void *aux)
{
    // 1. aux 구조체 형변환
    struct lazy_load_info *info = (struct lazy_load_info *) aux;

    // 2. 물리 프레임의 커널 주소 얻기
    uint8_t *kva = page->frame->kva;

    if (info->file != NULL)
    {
        // 3. 파일 오프셋 위치로 이동하여, 필요한 바이트 수만큼 읽기
        file_seek(info->file, info->offset);

        // 4. 남은 바이트를 0으로 채워 페이지 포맷 완성
        // 4-1. 읽은 byte 수가 같은지 확인하여 제대로 읽어졌는지 확인
        if (file_read(info->file, kva, info->bytes_read) !=
            (int) info->bytes_read)
        {
            palloc_free_page(kva);
            return false;
        }

        // 4-2. 나머지 바이트는 0으로 채우기
        memset(kva + info->bytes_read, 0, info->zero_bytes);
        return true;
    }

    return false;
}

/* FILE의 오프셋 OFS에서 시작하여 주소 UPAGE로 세그먼트를 로드합니다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다:
 *
 * - UPAGE의 READ_BYTES 바이트는 오프셋 OFS에서 시작하여 FILE에서 읽어야 합니다.
 *
 * - UPAGE + READ_BYTES의 ZERO_BYTES 바이트는 0으로 채워야 합니다.
 *
 * 이 함수에 의해 초기화된 페이지는 WRITABLE이 true이면 사용자 프로세스가
 * 수정할 수 있어야 하고, 그렇지 않으면 읽기 전용이어야 합니다.
 *
 * 성공하면 true를, 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를
 * 반환합니다. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable)
{
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* 이 페이지를 채우는 방법을 계산합니다.
         * FILE에서 PAGE_READ_BYTES 바이트를 읽고
         * 마지막 PAGE_ZERO_BYTES 바이트를 0으로 채웁니다. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        // lazy_load_segment에 정보를 전달하기 위해 aux를 설정
        struct lazy_load_info *aux = malloc(sizeof(struct lazy_load_info));
        //할당이 제대로 됐는지 예외 처리
        if (aux == NULL)
        {
            return false;
        }
        aux->file = file;
        aux->offset = ofs;
        aux->bytes_read = page_read_bytes;
        aux->zero_bytes = page_zero_bytes;

        // aux 동적 할당 해 준 거 언젠가 free 해야 할 것.... 시기를 잘 모르겠음

        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable,
                                            lazy_load_segment, aux))
            return false;

        /* 진행합니다. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
				ofs += page_read_bytes;
    }
    return true;
}

// aux 생성 및 초기화하는 함수
void aux_init(struct lazy_load_info *aux, struct file *file, off_t offset,
              uint32_t bytes_read, uint32_t zero_bytes)
{
    aux->file = file;
    aux->offset = offset;
    aux->bytes_read = bytes_read;
    aux->zero_bytes = zero_bytes;
}

/* USER_STACK에 스택의 PAGE를 생성합니다. 성공하면 true를 반환합니다. */
static bool setup_stack(struct intr_frame *if_)
{
    uint8_t *kpage;
    bool success = false;
    void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);
    struct thread *t = thread_current();

    /* TODO: stack_bottom에 스택을 매핑하고 즉시 페이지를 요청합니다.
     * TODO: 성공하면 rsp를 적절히 설정합니다.
     * TODO: 페이지가 스택임을 표시해야 합니다. */
    /* TODO: 여기에 코드를 작성하세요 */

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL)
    {
        success = (pml4_get_page(t->pml4, stack_bottom) == NULL &&
                   pml4_set_page(t->pml4, stack_bottom, kpage, true) &&
                    vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, true));
					/* success = (pml4_get_page(t->pml4, stack_bottom) == NULL 
					&& pml4_set_page(t->pml4, stack_bottom, kpage, true)
					&& vm_alloc_page(VM_ANON | VM_MARKER_0, setup_stack, true)) */
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page(kpage);
    }

    return success;
}
#endif /* VM */
