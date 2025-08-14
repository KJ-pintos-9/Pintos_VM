#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>

#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

/* 스레드 생명주기의 상태들 */
enum thread_status
{
    THREAD_RUNNING, /* 실행 중인 스레드 */
    THREAD_READY,   /* 실행 중이지 않지만 실행 준비된 상태 */
    THREAD_BLOCKED, /* 이벤트 트리거를 기다리는 상태 */
    THREAD_DYING    /* 파괴되려고 하는 상태 */
};

typedef enum fd_entry_type
{
    STDIO,
    FILE,
    DIRECTORY
} fd_entry_type;

/* 스레드 식별자 타입.
   원하는 타입으로 재정의할 수 있습니다. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1) /* tid_t의 에러 값 */

/* 스레드 우선순위 */
#define PRI_MIN 0      /* 최저 우선순위 */
#define PRI_DEFAULT 31 /* 기본 우선순위 */
#define PRI_MAX 63     /* 최고 우선순위 */

#define min(a, b) ((a) < (b) ? (a) : (b)) /* min값 찾기 */
#define max(a, b) ((a) > (b) ? (a) : (b)) /* max값 찾기 */

struct fdt_entry
{
    fd_entry_type type;
    void *entry;
};

/* 커널 스레드 또는 사용자 프로세스
 *
 * 각 스레드 구조체는 자체 4KB 페이지에 저장됩니다. 스레드 구조체 자체는
 * 페이지의 맨 아래(오프셋 0)에 위치합니다. 페이지의 나머지 부분은 스레드의
 * 커널 스택을 위해 예약되며, 이는 페이지 상단(오프셋 4KB)에서 아래로
 * 증가합니다. 다음은 그림입니다:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * 이것의 결과는 두 가지입니다:
 *
 *    1. 첫째, `struct thread`는 너무 커지도록 허용되어서는 안 됩니다.
 *       그렇게 되면 커널 스택을 위한 충분한 공간이 없을 것입니다.
 *       우리의 기본 `struct thread`는 몇 바이트 크기에 불과합니다.
 *       아마도 1KB 미만으로 유지되어야 할 것입니다.
 *
 *    2. 둘째, 커널 스택은 너무 크게 증가하도록 허용되어서는 안 됩니다.
 *       스택이 오버플로우되면 스레드 상태를 손상시킬 것입니다. 따라서
 *       커널 함수는 비정적 지역 변수로 큰 구조체나 배열을 할당해서는
 *       안 됩니다. 대신 malloc()이나 palloc_get_page()로 동적 할당을
 *       사용하세요.
 *
 * 이러한 문제들 중 하나의 첫 번째 증상은 아마도 thread_current()에서
 * 어설션 실패일 것입니다. 이는 실행 중인 스레드의 `struct thread`의
 * `magic` 멤버가 THREAD_MAGIC으로 설정되어 있는지 확인합니다.
 * 스택 오버플로우는 일반적으로 이 값을 변경하여 어설션을 트리거합니다. */
/* `elem` 멤버는 이중 목적을 가집니다. 실행 큐(thread.c)의 요소이거나
 * 세마포어 대기 목록(synch.c)의 요소일 수 있습니다. 이 두 가지 방법으로만
 * 사용할 수 있는 이유는 상호 배타적이기 때문입니다: 준비 상태의 스레드만
 * 실행 큐에 있고, 차단 상태의 스레드만 세마포어 대기 목록에 있습니다. */
struct thread
{
    /* thread.c가 소유 */
    tid_t tid;                 /* 스레드 식별자 */
    enum thread_status status; /* 스레드 상태 */
    char name[16];             /* 이름 (디버깅 목적) */
    int priority;              /* 실제 비교에 사용되는 priority */
    /* thread.c와 synch.c가 공유 */
    struct list_elem elem; /* 리스트 요소 */

    /* project 1.1 alarm wakeup 을 위한 구조체 */
    int64_t ticks; /* wake up time */

    /* project 1.3 priority_donation 을 위한 구조체 */
    int origin_priority; /* 쓰레드 생성 시 받은 priority */

    struct list donation_list; /* 나한테 기부한 쓰레드 목록 ( 내 우선순위 보다
                                  큰 값만 )*/
    struct list_elem donation_elem; /* 여러 donation list 와 연결될 수 있는 */

    struct lock *waiting_lock; /* 내가 기다리고 있는 락 */

    /* proejct 2 를 위한 구조체 */
    int exit_status; /* 프로세스 종료 코드 */
    bool is_exited; /* 종료 여부 확인, 부모 프로세스에 전달하는 용도 */
    struct intr_frame fork_if; /* fork() 호출 시점의 인터럽트 프레임, 자식
                                  프로세스에 넘겨줄 용도 */

    struct semaphore wait_sema; /* wait() 시스템 콜을 위한 세마포어 */
    bool is_waited;
    struct semaphore exit_sema; /* exit() 시스템 콜을 위한 세마포어 */
    struct semaphore fork_sema; /* fork() 시스템 콜을 위한 세마포어 */

    struct fdt_entry **fdt; /* 파일 디스크립터 테이블 포인터 */
    struct file *exec_file; /* exec()에 의해 실행 중인 파일 */

    struct list child_list; /* 자식 프로세스의 리스트 */
    struct list_elem
        child_elem; /* 자식 프로세스가 부모 프로세스에 포함되기 위한 구조체? */
    struct thread *parent_process; /* 부모 프로세스, 자식 스레드를 만들고 있는
                                      스레드를 thread_current()로 넣어줌 */

    void *user_rsp;
#ifdef USERPROG
    /* userprog/process.c가 소유 */
    uint64_t *pml4; /* 페이지 맵 레벨 4 */
#endif
#ifdef VM
    /* 스레드가 소유한 전체 가상 메모리를 위한 테이블 */
    struct supplemental_page_table spt;
#endif

    /* thread.c가 소유 */
    struct intr_frame tf; /* 스위칭을 위한 정보 */
    unsigned magic;       /* 스택 오버플로우 감지 */
};

/* false(기본값)이면 라운드 로빈 스케줄러를 사용합니다.
   true이면 다단계 피드백 큐 스케줄러를 사용합니다.
   커널 명령줄 옵션 "-o mlfqs"로 제어됩니다. */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

/* project 1.1 alarm 을 위한 커스텀 함수 목록 */
void thread_sleep(int64_t ticks);
bool cmp_ticks(const struct list_elem *a, const struct list_elem *b, void *aux);
void thread_wakeup();
int64_t get_minimum_tick(void);
void set_minimum_tick(void);
/* project 1.1 alarm 을 위한 커스텀 함수 목록 */

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);
/* project 2 를 위한 try_yield 함수 */
void thread_try_yield();

int thread_get_priority(void);
void thread_set_priority(int);
/* project 1.3 priority 를 위한 커스텀 함수 */
bool cmp_prioirty(const struct list_elem *a, const struct list_elem *b,
                  void *aux);
int thread_max_priority(struct thread *t);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

#endif /* threads/thread.h */
