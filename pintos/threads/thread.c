#include "threads/thread.h"

#include <debug.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "threads/malloc.h"
#include "userprog/process.h"
#endif

/* struct thread의 'magic' 멤버를 위한 랜덤 값.
   스택 오버플로우를 감지하는 데 사용됩니다. 자세한 내용은
   thread.h 상단의 큰 주석을 참조하세요. */
#define THREAD_MAGIC 0xcd6abf4b

/* 기본 스레드를 위한 랜덤 값
   이 값을 수정하지 마세요. */
#define THREAD_BASIC 0xd42df210

/* THREAD_READY 상태의 프로세스 목록, 즉 실행 준비가 되었지만
   실제로 실행되지 않는 프로세스들입니다. */
static struct list ready_list;

/* 쉬는 상태의 쓰레드 목록, 즉 BLOCK 된 쓰레드들 입니다. */
static struct list sleep_list;

/* 접근할 수 없는 공유자원을 기다리는 쓰레드들 입니다. */
static struct list wait_list;

/* 유휴 스레드. */
static struct thread *idle_thread;

/* 초기 스레드, init.c:main()을 실행하는 스레드. */
static struct thread *initial_thread;

/* allocate_tid()에서 사용하는 락. */
static struct lock tid_lock;

/* 스레드 소멸 요청 */
static struct list destruction_req;

/* 통계. */
static long long idle_ticks; /* 유휴 상태에서 소비된 타이머 틱 수. */
static long long kernel_ticks; /* 커널 스레드에서 소비된 타이머 틱 수. */
static long long user_ticks; /* 사용자 프로그램에서 소비된 타이머 틱 수. */

/* 스케줄링. */
#define TIME_SLICE 4 /* 각 스레드에 할당할 타이머 틱 수. */
static unsigned thread_ticks; /* 마지막 양보 이후 타이머 틱 수. */

/* alarm 구현을 위한 minimum tick */
static int64_t minimum_tick =
    INT64_MAX; /* Sleep_list 에 있는 쓰레드 tick 중 가장 작은 값 */

/* false(기본값)이면 라운드 로빈 스케줄러를 사용합니다.
   true이면 다단계 피드백 큐 스케줄러를 사용합니다.
   커널 명령줄 옵션 "-o mlfqs"로 제어됩니다. */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

/* T가 유효한 스레드를 가리키는 것으로 보이면 true를 반환합니다. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* 실행 중인 스레드를 반환합니다.
 * CPU의 스택 포인터 'rsp'를 읽고, 이를 페이지의 시작 부분으로
 * 내림합니다. 'struct thread'는 항상 페이지의 시작 부분에 있고
 * 스택 포인터는 중간 어딘가에 있기 때문에, 이는 현재 스레드를
 * 찾아냅니다. */
#define running_thread() ((struct thread *) (pg_round_down(rrsp())))

// thread_start를 위한 전역 디스크립터 테이블.
// gdt는 thread_init 이후에 설정되기 때문에, 먼저 임시 gdt를
// 설정해야 합니다.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* 현재 실행 중인 코드를 스레드로 변환하여 스레딩 시스템을 초기화합니다.
   이는 일반적으로 작동하지 않으며, loader.S가 스택의 하단을 페이지
   경계에 신중하게 배치했기 때문에 이 경우에만 가능합니다.

   또한 실행 큐와 tid 락을 초기화합니다.

   이 함수를 호출한 후에는 thread_create()로 스레드를 생성하기 전에
   페이지 할당자를 초기화해야 합니다.

   이 함수가 완료되기 전까지는 thread_current()를 호출하는 것이
   안전하지 않습니다. */
void thread_init(void)
{
    ASSERT(intr_get_level() == INTR_OFF);

    /* 커널을 위한 임시 gdt를 다시 로드합니다.
     * 이 gdt는 사용자 컨텍스트를 포함하지 않습니다.
     * 커널은 gdt_init()에서 사용자 컨텍스트와 함께 gdt를 재구성합니다. */
    struct desc_ptr gdt_ds = {.size = sizeof(gdt) - 1,
                              .address = (uint64_t) gdt};
    lgdt(&gdt_ds);

    /* 전역 스레드 컨텍스트를 초기화합니다. */
    lock_init(&tid_lock);

    list_init(&ready_list);
    list_init(&sleep_list);
    list_init(&destruction_req);

    /* 실행 중인 스레드를 위한 스레드 구조체를 설정합니다. */
    initial_thread = running_thread();
    init_thread(initial_thread, "main", PRI_DEFAULT);
    initial_thread->status = THREAD_RUNNING;
    initial_thread->tid = allocate_tid();
}

/* 인터럽트를 활성화하여 선점형 스레드 스케줄링을 시작합니다.
   또한 유휴 스레드를 생성합니다. */
void thread_start(void)
{
    /* 유휴 스레드를 생성합니다. */
    struct semaphore idle_started;
    sema_init(&idle_started, 0);
    thread_create("idle", PRI_MIN, idle, &idle_started);

    /* 선점형 스레드 스케줄링을 시작합니다. */
    intr_enable();

    /* 유휴 스레드가 idle_thread를 초기화할 때까지 기다립니다. */
    sema_down(&idle_started);
}

/* 각 타이머 틱마다 타이머 인터럽트 핸들러에 의해 호출됩니다.
   따라서 이 함수는 외부 인터럽트 컨텍스트에서 실행됩니다. */
void thread_tick(void)
{
    struct thread *t = thread_current();

    /* 통계를 업데이트합니다. */
    if (t == idle_thread) idle_ticks++;
#ifdef USERPROG
    else if (t->pml4 != NULL)
        user_ticks++;
#endif
    else
        kernel_ticks++;

    /* 선점을 강제합니다. */
    if (++thread_ticks >= TIME_SLICE) intr_yield_on_return();
}

/* 스레드 통계를 출력합니다. */
void thread_print_stats(void)
{
    printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
           idle_ticks, kernel_ticks, user_ticks);
}

/* 주어진 초기 PRIORITY로 NAME이라는 새로운 커널 스레드를 생성하고,
   AUX를 인수로 전달하여 FUNCTION을 실행하며, ready 큐에 추가합니다.
   새 스레드의 스레드 식별자를 반환하거나, 생성에 실패하면 TID_ERROR를
   반환합니다.

   thread_start()가 호출되었다면, 새 스레드는 thread_create()가 반환되기
   전에 스케줄될 수 있습니다. thread_create()가 반환되기 전에 종료될 수도
   있습니다. 반대로, 원래 스레드는 새 스레드가 스케줄되기 전에 임의의
   시간 동안 실행될 수 있습니다. 순서를 보장해야 한다면 세마포어나 다른
   형태의 동기화를 사용하세요.

   제공된 코드는 새 스레드의 'priority' 멤버를 PRIORITY로 설정하지만,
   실제 우선순위 스케줄링은 구현되지 않았습니다.
   우선순위 스케줄링은 Problem 1-3의 목표입니다. */
tid_t thread_create(const char *name, int priority, thread_func *function,
                    void *aux)
{
    struct thread *t;

    tid_t tid;

    ASSERT(function != NULL);

    /* 스레드를 할당합니다. */
    t = palloc_get_page(PAL_ZERO);
    if (t == NULL) return TID_ERROR;

    /* 스레드를 초기화합니다. */
    init_thread(t, name, priority);
    tid = t->tid = allocate_tid();

    /* 파일 디스크립터 테이블 초기화 */
    void *fdt = calloc(128, sizeof(char *));
    t->fdt = fdt;
    // t->next_fd = 3;
    for (int i = 0; i < 3; i++)
    {
        t->fdt[i] = calloc(
            1,
            sizeof(struct fdt_entry));  // fd : 0~2까지만 공간 할당, 나머지는
                                        // 알아서 NULL (calloc으로 받았으니까)
    }

    t->exec_file = NULL;

    /* 부모-자식 프로세스 관계 설정 */
    t->parent_process = thread_current();
    list_push_back(&thread_current()->child_list, &t->child_elem);

    /* 스케줄되면 kernel_thread를 호출합니다.
     * 참고) rdi는 첫 번째 인수이고, rsi는 두 번째 인수입니다. */
    t->tf.rip = (uintptr_t) kernel_thread;
    t->tf.R.rdi = (uint64_t) function;
    t->tf.R.rsi = (uint64_t) aux;
    t->tf.ds = SEL_KDSEG;
    t->tf.es = SEL_KDSEG;
    t->tf.ss = SEL_KDSEG;
    t->tf.cs = SEL_KCSEG;
    t->tf.eflags = FLAG_IF;

    /* 실행 큐에 추가합니다. */
    enum intr_level old_level = intr_disable();
    thread_unblock(t);

    /* 현재 쓰레드와 방금 입력된 쓰레드를 비교해서 실행 쓰레드를 갱신합니다. */
    if (thread_current()->priority < t->priority)
    {
        intr_set_level(old_level);
        thread_yield();
    }
    else
    {
        intr_set_level(old_level);
    }

    return tid;
}

/* 현재 스레드를 잠들게 합니다. thread_unblock()에 의해 깨어나기 전까지는
   다시 스케줄되지 않습니다.
   이 함수는 인터럽트가 꺼진 상태에서 호출되어야 합니다. 보통은
   synch.h의 동기화 프리미티브 중 하나를 사용하는 것이 더 좋습니다. */
void thread_block(void)
{
    ASSERT(!intr_context());
    ASSERT(intr_get_level() == INTR_OFF);
    thread_current()->status = THREAD_BLOCKED;
    schedule();
}

/*
    project 1.3 priority 를 위한 함수
    리스트를 prioirty 로 오름차순 정렬 insert 할 때 사용합니다.
    a는 새로 입력된 쓰레드 b는 기존에 리스트에 있던 쓰레드 입니다.
*/
bool cmp_prioirty(const struct list_elem *a, const struct list_elem *b,
                  void *aux)
{
    int new_prioirity = list_entry(a, struct thread, elem)->priority;
    int list_priority = list_entry(b, struct thread, elem)->priority;

    return new_prioirity > list_priority;
}

/* 차단된 스레드 T를 실행 준비 상태로 전환합니다.
   T가 차단되지 않은 경우 오류입니다. (실행 중인 스레드를 준비 상태로
   만들려면 thread_yield()를 사용하세요.)

   이 함수는 실행 중인 스레드를 선점하지 않습니다. 이는 중요할 수 있습니다:
   호출자가 스스로 인터럽트를 비활성화했다면, 스레드를 원자적으로 차단 해제하고
   다른 데이터를 업데이트할 수 있다고 기대할 수 있습니다. */
void thread_unblock(struct thread *t)
{
    enum intr_level old_level;

    ASSERT(is_thread(t));

    old_level = intr_disable();
    ASSERT(t->status == THREAD_BLOCKED);

    list_insert_ordered(&ready_list, &t->elem, cmp_prioirty, NULL);
    t->status = THREAD_READY;

    intr_set_level(old_level);
}

/* 실행 중인 스레드의 이름을 반환합니다. */
const char *thread_name(void)
{
    return thread_current()->name;
}

/* 실행 중인 스레드를 반환합니다.
   이는 running_thread()에 몇 가지 온전성 검사를 추가한 것입니다.
   자세한 내용은 thread.h 상단의 큰 주석을 참조하세요. */
struct thread *thread_current(void)
{
    struct thread *t = running_thread();

    /* T가 실제로 스레드인지 확인합니다.
       이 어설션 중 하나라도 발생하면, 스레드가 스택을 오버플로우했을
       수 있습니다. 각 스레드는 4KB 미만의 스택을 가지므로, 몇 개의
       큰 자동 배열이나 적당한 재귀가 스택 오버플로우를 일으킬 수 있습니다. */
    ASSERT(is_thread(t));
    ASSERT(t->status == THREAD_RUNNING);

    return t;
}

/* 현재 실행중인 thread의 tid를 반환합니다. */
tid_t thread_tid(void)
{
    return thread_current()->tid;
}

/* 현재 스레드의 스케줄을 해제하고 소멸시킵니다.
   호출자에게 절대 반환되지 않습니다. */
void thread_exit(void)
{
    ASSERT(!intr_context());
    struct thread *t = thread_current();
    
    // intr_disable(); 위치 이동
    // sema_up(&thread_current()->wait_sema); -> 이거 exit()으로 옮김

#ifdef USERPROG
    process_exit();
#endif

    /* 상태를 dying으로 설정하고 다른 프로세스를 스케줄합니다.
       schedule_tail() 호출 중에 소멸됩니다. */
    sema_up(&t->wait_sema);  // 위치 여기 아닐수도 있음
    sema_down(&t->exit_sema);

    t->is_waited = false;
    t->is_exited = true;

    list_remove(&t->child_elem);

    free(t->waiting_lock);

    for (int i = 0; i < 128; i++)
    {
        if (t->fdt[i] != NULL) free(t->fdt[i]);
    }

    free(t->fdt);
    free(t->exec_file);

    intr_disable();
    do_schedule(THREAD_DYING);
    NOT_REACHED();
}

/* CPU를 양보합니다. 현재 스레드는 잠들지 않으며
   스케줄러의 판단에 따라 즉시 다시 스케줄될 수 있습니다. */
void thread_yield(void)
{
    struct thread *curr = thread_current();
    enum intr_level old_level;

    ASSERT(!intr_context());

    old_level = intr_disable();

    // 현재 스레드가 유휴 스레드가 아니면 ready_list 에 넣습니다.
    if (curr != idle_thread)
        list_insert_ordered(&ready_list, &curr->elem, cmp_prioirty, NULL);

    do_schedule(THREAD_READY);
    intr_set_level(old_level);
}

/*
사용하는 이유
- idle_thread가 잘못 yield하지 않도록 보호
- ready_list가 비어 있는 상황에서 불필요한 switch 방지
- assert 실패 방지
*/
void thread_try_yield()
{
    enum intr_level old_level = intr_disable();

    if (!list_empty(&ready_list) &&
        thread_current()->priority <
            list_entry(list_front(&ready_list), struct thread, elem)->priority)
    {
        if (intr_context())
        {
            intr_yield_on_return();
        }
        else
        {
            thread_yield();
        }
    }

    intr_set_level(old_level);
}

/*
    project 1.1 alarm 을 위한 함수
    리스트를 ticks 기준으로 내림차순 정렬 insert 할 때 사용합니다.
    a는 방금 입력된 쓰레드, b는 기존에 리스트에 있던 쓰레드 입니다.
*/
bool cmp_ticks(const struct list_elem *a, const struct list_elem *b, void *aux)
{
    int a_ticks = list_entry(a, struct thread, elem)->ticks;
    int b_ticks = list_entry(b, struct thread, elem)->ticks;

    return a_ticks < b_ticks;
}

/*
    project 1.1 alarm 을 위해 추가된 함수
    ㅋㅋ 이거 찾아보셈
    현재 쓰레드를 ticks 초 동안 쉬게 만듭니다.
*/
void thread_sleep(int64_t ticks)
{
    struct thread *t = thread_current();

    /* 쓰레드 리스트를 조작할 때는 인터럽트를 비활성화 시키기 */
    enum intr_level old_level = intr_disable();

    /* 1. 현재 스레드가 idle 쓰레드가 아니라면 */
    if (t != idle_thread)
    {
        /* 2. 깨울 시점의 tick 값을 저장 */
        t->ticks = ticks;

        /* 3. sleep list에 ticks 값 기준으로 정렬 */
        list_insert_ordered(&sleep_list, &t->elem, cmp_ticks, NULL);

        /* 4. minimum_tick 갱신 */
        set_minimum_tick();

        /* thread 를 sleep_list 로 */
        thread_block();
    }

    intr_set_level(old_level);
}

/*
    project 1.1 alarm을 위한 함수
    sleep_list 에서 조건에 맞는 thread를 ready_list로 옮겨줍니다.
*/
void thread_wakeup()
{
    struct list_elem *e;

    enum intr_level old_level = intr_disable();

    e = list_begin(&sleep_list);

    while (e != list_end(&sleep_list))
    {
        struct list_elem *next = list_next(e);
        struct thread *current = list_entry(e, struct thread, elem);

        if (current->ticks <= timer_ticks())
        {
            list_remove(e);
            thread_unblock(current);

            /*
                thread_wakeup 은 무조건 timer interrupt 안에서 호출됩니다.
                따라서 thread_yield 가 아닌 intr_yield_on_return 을 사용해줘야
               안전합니다.
            */
            intr_yield_on_return();
        }
        else
        {
            break;
        }

        e = next;
    }

    /* sleep_list가 변경되었을 가능성이 있으므로 min_tick 을 갱신해줍니다. */
    set_minimum_tick();
    intr_set_level(old_level);
}

/*
    project 1.1 alarm 을 위한 함수
    minimum_tick 을 sleep_list의 가장 작은 tick과 비교해서 갱신합니다.
    set_minimum_tick 은 intr 을 멈춘 상황에서만 호출되기 때문에,
    사용하지 않아도 안전합니다.

    다만 더 보안에 신경쓰고 싶다면 intr 를 호출해도 상관 없습니다.
*/
void set_minimum_tick(void)
{
    ASSERT(intr_get_level() == INTR_OFF);

    minimum_tick = INT64_MAX;

    if (list_empty(&sleep_list))
    {
        return;
    }

    struct thread *t = list_entry(list_begin(&sleep_list), struct thread, elem);
    minimum_tick = min(minimum_tick, t->ticks);
}

/*
    project 1.1 alarm 을 위한 함수
    minimum_tick 값을 반환합니다.
*/
int64_t get_minimum_tick(void)
{
    enum intr_level old_level = intr_disable();
    int64_t m = minimum_tick;
    intr_set_level(old_level);
    barrier();
    return m;
};

/*
    project 1.3 priority_donation 에서 필요한 쓰레드에서 가장 높은 우선순위를
   반환하는 함수
*/
int thread_max_priority(struct thread *t)
{
    if (list_empty(&t->donation_list))
    {
        return t->origin_priority;
    }
    else
    {
        return max(t->origin_priority, list_entry(list_begin(&t->donation_list),
                                                  struct thread, donation_elem)
                                           ->priority);
    }
}

/* 현재 스레드의 우선순위를 NEW_PRIORITY로 설정합니다. */
/* 현재 스레드의 우선순위를 새 우선순위로 설정합니다. */
/* 만약 현재 스레드의 우선순위가 더 이상 높지 않으면 우선순위를 양보합니다. */
void thread_set_priority(int new_priority)
{
    enum intr_level old_level = intr_disable();
    struct thread *t = thread_current();
    t->origin_priority = new_priority;
    t->priority = thread_max_priority(t);
    /* TODO : priority 가 변경된 후 , donation_list 를 살펴보고 가장 높은 걸로
     * 갱신? */

    if (t->priority <
        list_entry(list_begin(&ready_list), struct thread, elem)->priority)
    {
        intr_set_level(old_level);
        thread_yield();
    }
    else
    {
        intr_set_level(old_level);
    }
}

/* 현재 스레드의 우선순위를 반환합니다. */
/* 우선 순위 기부가 있는 경우 더 높은 (기부된) 우선순위를 반환합니다. */
int thread_get_priority(void)
{
    return thread_current()->priority;
}

/* 현재 스레드의 nice 값을 NICE로 설정합니다. */
void thread_set_nice(int nice UNUSED)
{
    /* TODO: 여기에 구현을 추가하세요 */
}

/* 현재 스레드의 nice 값을 반환합니다. */
int thread_get_nice(void)
{
    /* TODO: 여기에 구현을 추가하세요 */
    return 0;
}

/* 시스템 로드 평균의 100배를 반환합니다. */
int thread_get_load_avg(void)
{
    /* TODO: 여기에 구현을 추가하세요 */
    return 0;
}

/* 현재 스레드의 recent_cpu 값의 100배를 반환합니다. */
int thread_get_recent_cpu(void)
{
    /* TODO: 여기에 구현을 추가하세요 */
    return 0;
}

/* 유휴 스레드. 다른 스레드가 실행 준비가 되지 않았을 때 실행됩니다.

   유휴 스레드는 처음에 thread_start()에 의해 ready 목록에 추가됩니다.
   처음에 한 번 스케줄되어, 이 시점에서 idle_thread를 초기화하고,
   전달받은 세마포어를 "up"하여 thread_start()가 계속 진행할 수 있도록 하고,
   즉시 차단됩니다. 그 후 유휴 스레드는 ready 목록에 나타나지 않습니다.
   ready 목록이 비어있을 때 next_thread_to_run()에 의해 특별한 경우로
   반환됩니다. */
static void idle(void *idle_started_ UNUSED)
{
    struct semaphore *idle_started = idle_started_;

    idle_thread = thread_current();
    sema_up(idle_started);

    for (;;)
    {
        /* 다른 누군가가 실행하도록 합니다. */
        intr_disable();
        thread_block();

        /* 인터럽트를 다시 활성화하고 다음 인터럽트를 기다립니다.

           'sti' 명령은 다음 명령이 완료될 때까지 인터럽트를 비활성화하므로,
           이 두 명령은 원자적으로 실행됩니다. 이 원자성은 중요합니다;
           그렇지 않으면 인터럽트를 다시 활성화하는 것과 다음 인터럽트를
           기다리는 것 사이에 인터럽트가 처리될 수 있어, 최대 한 클록 틱
           분량의 시간을 낭비할 수 있습니다.

           [IA32-v2a] "HLT", [IA32-v2b] "STI", [IA32-v3a] 7.11.1 "HLT
           Instruction"을 참조하세요. */
        asm volatile("sti; hlt" : : : "memory");
    }
}

/* 커널 스레드의 기반으로 사용되는 함수. */
static void kernel_thread(thread_func *function, void *aux)
{
    ASSERT(function != NULL);

    intr_enable(); /* 스케줄러는 인터럽트가 꺼진 상태에서 실행됩니다. */
    function(aux); /* 스레드 함수를 실행합니다. */
    thread_exit(); /* function()이 반환되면 스레드를 종료합니다. */
}

/* T를 NAME이라는 이름의 차단된 스레드로 기본 초기화합니다. */
static void init_thread(struct thread *t, const char *name, int priority)
{
    ASSERT(t != NULL);
    ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
    ASSERT(name != NULL);

    memset(t, 0, sizeof *t);
    t->status = THREAD_BLOCKED;
    strlcpy(t->name, name, sizeof t->name);
    t->tf.rsp = (uint64_t) t + PGSIZE - sizeof(void *);
    t->priority = priority;
    t->magic = THREAD_MAGIC;

    /* proejct 1.3 priority_donation을 위한 쓰레드 구조체 초기화 */
    t->origin_priority = priority;
    t->waiting_lock = NULL;

    t->is_exited = false;
    t->is_waited = false;

    /* wait_sema, exec_sema, fork_sema 초기화 */
    sema_init(&t->wait_sema, 0);
    sema_init(&t->exit_sema, 0);
    sema_init(&t->fork_sema, 0);

    list_init(&t->child_list);

    list_init(&t->donation_list);
}

/* 스케줄될 다음 스레드를 선택하고 반환합니다. 실행 큐가 비어있지 않다면
   실행 큐에서 스레드를 반환해야 합니다. (실행 중인 스레드가 계속 실행될 수
   있다면, 실행 큐에 있을 것입니다.) 실행 큐가 비어있으면 idle_thread를
   반환합니다. */
static struct thread *next_thread_to_run(void)
{
    if (list_empty(&ready_list))
        return idle_thread;
    else
        return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* iretq를 사용하여 스레드를 시작합니다 */
void do_iret(struct intr_frame *tf)
{
    __asm __volatile(
        "movq %0, %%rsp\n"
        "movq 0(%%rsp),%%r15\n"
        "movq 8(%%rsp),%%r14\n"
        "movq 16(%%rsp),%%r13\n"
        "movq 24(%%rsp),%%r12\n"
        "movq 32(%%rsp),%%r11\n"
        "movq 40(%%rsp),%%r10\n"
        "movq 48(%%rsp),%%r9\n"
        "movq 56(%%rsp),%%r8\n"
        "movq 64(%%rsp),%%rsi\n"
        "movq 72(%%rsp),%%rdi\n"
        "movq 80(%%rsp),%%rbp\n"
        "movq 88(%%rsp),%%rdx\n"
        "movq 96(%%rsp),%%rcx\n"
        "movq 104(%%rsp),%%rbx\n"
        "movq 112(%%rsp),%%rax\n"
        "addq $120,%%rsp\n"
        "movw 8(%%rsp),%%ds\n"
        "movw (%%rsp),%%es\n"
        "addq $32, %%rsp\n"
        "iretq"
        :
        : "g"((uint64_t) tf)
        : "memory");
}

/* 새 스레드의 페이지 테이블을 활성화하여 스레드를 전환하고,
   이전 스레드가 dying 상태라면 소멸시킵니다.

   이 함수가 호출될 때, 방금 스레드 PREV에서 전환되었고,
   새 스레드는 이미 실행 중이며, 인터럽트는 여전히 비활성화되어 있습니다.

   스레드 전환이 완료되기 전까지는 printf()를 호출하는 것이 안전하지 않습니다.
   실제로는 함수의 끝에 printf()를 추가해야 한다는 의미입니다. */
static void thread_launch(struct thread *th)
{
    uint64_t tf_cur = (uint64_t) &running_thread()->tf;
    uint64_t tf = (uint64_t) &th->tf;
    ASSERT(intr_get_level() == INTR_OFF);

    /* 주요 전환 로직.
     * 먼저 전체 실행 컨텍스트를 intr_frame으로 복원한 다음
     * do_iret을 호출하여 다음 스레드로 전환합니다.
     * 참고로, 전환이 완료될 때까지 여기서부터는 스택을 사용하면 안 됩니다. */
    __asm __volatile(
        /* 사용할 레지스터를 저장합니다. */
        "push %%rax\n"
        "push %%rbx\n"
        "push %%rcx\n"
        /* 입력을 한 번 가져옵니다 */
        "movq %0, %%rax\n"
        "movq %1, %%rcx\n"
        "movq %%r15, 0(%%rax)\n"
        "movq %%r14, 8(%%rax)\n"
        "movq %%r13, 16(%%rax)\n"
        "movq %%r12, 24(%%rax)\n"
        "movq %%r11, 32(%%rax)\n"
        "movq %%r10, 40(%%rax)\n"
        "movq %%r9, 48(%%rax)\n"
        "movq %%r8, 56(%%rax)\n"
        "movq %%rsi, 64(%%rax)\n"
        "movq %%rdi, 72(%%rax)\n"
        "movq %%rbp, 80(%%rax)\n"
        "movq %%rdx, 88(%%rax)\n"
        "pop %%rbx\n"  // 저장된 rcx
        "movq %%rbx, 96(%%rax)\n"
        "pop %%rbx\n"  // 저장된 rbx
        "movq %%rbx, 104(%%rax)\n"
        "pop %%rbx\n"  // 저장된 rax
        "movq %%rbx, 112(%%rax)\n"
        "addq $120, %%rax\n"
        "movw %%es, (%%rax)\n"
        "movw %%ds, 8(%%rax)\n"
        "addq $32, %%rax\n"
        "call __next\n"  // 현재 rip를 읽습니다.
        "__next:\n"
        "pop %%rbx\n"
        "addq $(out_iret -  __next), %%rbx\n"
        "movq %%rbx, 0(%%rax)\n"  // rip
        "movw %%cs, 8(%%rax)\n"   // cs
        "pushfq\n"
        "popq %%rbx\n"
        "mov %%rbx, 16(%%rax)\n"  // eflags
        "mov %%rsp, 24(%%rax)\n"  // rsp
        "movw %%ss, 32(%%rax)\n"
        "mov %%rcx, %%rdi\n"
        "call do_iret\n"
        "out_iret:\n"
        :
        : "g"(tf_cur), "g"(tf)
        : "memory");
}

/* 새 프로세스를 스케줄합니다. 진입 시 인터럽트가 꺼져 있어야 합니다.
 * 이 함수는 현재 스레드의 상태를 status로 수정한 다음
 * 실행할 다른 스레드를 찾아 전환합니다.
 * schedule()에서 printf()를 호출하는 것은 안전하지 않습니다. */
static void do_schedule(int status)
{
    ASSERT(intr_get_level() == INTR_OFF);
    ASSERT(thread_current()->status == THREAD_RUNNING);

    while (!list_empty(&destruction_req))
    {
        struct thread *victim =
            list_entry(list_pop_front(&destruction_req), struct thread, elem);
        palloc_free_page(victim);
    }

    thread_current()->status = status;
    schedule();
}

static void schedule(void)
{
    struct thread *curr = running_thread();
    struct thread *next = next_thread_to_run();

    ASSERT(intr_get_level() == INTR_OFF);
    ASSERT(curr->status != THREAD_RUNNING);
    ASSERT(is_thread(next));
    /* 실행 중으로 표시합니다. */
    next->status = THREAD_RUNNING;

    /* 새 타임 슬라이스를 시작합니다. */
    thread_ticks = 0;

#ifdef USERPROG
    /* 새 주소 공간을 활성화합니다. */
    process_activate(next);
#endif

    if (curr != next)
    {
        /* 전환한 스레드가 dying 상태라면, 해당 struct thread를 소멸시킵니다.
           thread_exit()가 자신의 발밑을 빼지 않도록 늦게 발생해야 합니다.
           페이지가 현재 스택에서 사용되고 있기 때문에 여기서는 페이지 해제
           요청만 큐에 넣습니다.
           실제 소멸 로직은 schedule()의 시작 부분에서 호출됩니다. */
        if (curr && curr->status == THREAD_DYING && curr != initial_thread)
        {
            ASSERT(curr != next);
            list_push_back(&destruction_req, &curr->elem);
        }

        /* 스레드를 전환하기 전에, 먼저 현재 실행 중인 스레드의 정보를
         * 저장합니다. */
        thread_launch(next);
    }
}

/* 새 스레드에 사용할 tid를 반환합니다. */
static tid_t allocate_tid(void)
{
    static tid_t next_tid = 1;
    tid_t tid;

    lock_acquire(&tid_lock);
    tid = next_tid++;
    lock_release(&tid_lock);

    return tid;
}
