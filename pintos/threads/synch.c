/* 이 파일은 Nachos 교육용 운영체제의 소스 코드에서 파생되었습니다.
   Nachos 저작권 고지는 아래에 전체가 재생산되어 있습니다. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   이 소프트웨어와 관련 문서를 수수료 없이 그리고 서면 계약 없이 어떤 목적으로든
   사용, 복사, 수정, 배포할 수 있는 권한이 위의 저작권 고지와 다음 두 단락이
   이 소프트웨어의 모든 사본에 나타나는 조건 하에 허가됩니다.

   캘리포니아 대학교는 이 소프트웨어와 관련 문서의 사용으로 인해 발생하는
   직접적, 간접적, 특별한, 부수적 또는 결과적 손해에 대해 어떤 당사자에게도
   책임을 지지 않습니다. 이는 캘리포니아 대학교가 그러한 손해의 가능성에 대해
   사전에 통보받은 경우에도 마찬가지입니다.

   캘리포니아 대학교는 특정 목적에 대한 적합성의 묵시적 보증을 포함하되 이에
   국한되지 않는 모든 보증을 명시적으로 부인합니다. 여기에 제공된 소프트웨어는
   "있는 그대로" 제공되며, 캘리포니아 대학교는 유지보수, 지원, 업데이트,
   개선사항 또는 수정사항을 제공할 의무가 없습니다.
   */

#include "threads/synch.h"

#include <stdio.h>
#include <string.h>

#include "threads/interrupt.h"
#include "threads/thread.h"

/* 세마포어 SEMA를 VALUE로 초기화합니다. 세마포어는 음이 아닌 정수이며
   이를 조작하는 두 개의 원자적 연산자를 가집니다:

   - down 또는 "P": 값이 양수가 될 때까지 기다린 후 감소시킵니다.

   - up 또는 "V": 값을 증가시킵니다 (대기 중인 스레드가 있다면 하나를 깨웁니다).
 */
void sema_init(struct semaphore *sema, unsigned value)
{
    ASSERT(sema != NULL);

    sema->value = value;
    list_init(&sema->waiters);
}

/* 세마포어에서 Down 또는 "P" 연산입니다. SEMA의 값이 양수가 될 때까지 기다린 후
   원자적으로 감소시킵니다.

   이 함수는 슬립할 수 있으므로 인터럽트 핸들러 내에서 호출되어서는 안 됩니다.
   이 함수는 인터럽트가 비활성화된 상태에서 호출될 수 있지만, 슬립하는 경우
   다음에 스케줄된 스레드가 아마도 인터럽트를 다시 켤 것입니다.
   이것은 sema_down 함수입니다. */
void sema_down(struct semaphore *sema)
{
    enum intr_level old_level;

    ASSERT(sema != NULL);
    ASSERT(!intr_context());

    old_level = intr_disable();
    while (sema->value == 0)
    {
        /* project 1.3 priority 를 위해 변경된 함수 */
        list_insert_ordered(&sema->waiters, &thread_current()->elem,
                            cmp_prioirty, NULL);
        thread_block();
    }
    sema->value--;

    intr_set_level(old_level);
}

/* 세마포어에서 Down 또는 "P" 연산이지만, 세마포어가 이미 0이 아닌 경우에만
   수행됩니다. 세마포어가 감소되면 true를 반환하고, 그렇지 않으면 false를
   반환합니다.

   이 함수는 인터럽트 핸들러에서 호출될 수 있습니다. */
bool sema_try_down(struct semaphore *sema)
{
    enum intr_level old_level;
    bool success;

    ASSERT(sema != NULL);

    old_level = intr_disable();
    if (sema->value > 0)
    {
        sema->value--;
        success = true;
    }
    else
        success = false;
    intr_set_level(old_level);

    return success;
}

/* 세마포어에서 Up 또는 "V" 연산입니다. SEMA의 값을 증가시키고
   SEMA를 기다리는 스레드 중 하나를 깨웁니다(있다면).

   이 함수는 인터럽트 핸들러에서 호출될 수 있습니다. */
void sema_up(struct semaphore *sema)
{
    enum intr_level old_level;

    ASSERT(sema != NULL);

    old_level = intr_disable();
    if (!list_empty(&sema->waiters))
    {
        list_sort(&sema->waiters, cmp_prioirty, NULL);

        struct thread *t =
            list_entry(list_pop_front(&sema->waiters), struct thread, elem);
        thread_unblock(t);
    }

    sema->value++;
    intr_set_level(old_level);

    thread_try_yield();

    //    thread_yield();
}

static void sema_test_helper(void *sema_);

/* 한 쌍의 스레드 사이에서 제어를 "핑퐁"하도록 하는 세마포어 자체 테스트입니다.
   무엇이 일어나는지 보려면 printf() 호출을 삽입하세요. */
void sema_self_test(void)
{
    struct semaphore sema[2];
    int i;

    printf("Testing semaphores...");
    sema_init(&sema[0], 0);
    sema_init(&sema[1], 0);
    thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
    for (i = 0; i < 10; i++)
    {
        sema_up(&sema[0]);
        sema_down(&sema[1]);
    }
    printf("done.\n");
}

/* sema_self_test()에서 사용하는 스레드 함수입니다. */
static void sema_test_helper(void *sema_)
{
    struct semaphore *sema = sema_;
    int i;

    for (i = 0; i < 10; i++)
    {
        sema_down(&sema[0]);
        sema_up(&sema[1]);
    }
}

/* LOCK을 초기화합니다. 락은 주어진 시간에 최대 하나의 스레드만 보유할 수
   있습니다. 우리의 락은 "재귀적"이지 않습니다. 즉, 현재 락을 보유하고 있는
   스레드가 그 락을 다시 획득하려고 시도하는 것은 오류입니다.

   락은 초기값이 1인 세마포어의 특수화입니다. 락과 그러한 세마포어의 차이점은
   두 가지입니다. 첫째, 세마포어는 1보다 큰 값을 가질 수 있지만, 락은 한 번에
   하나의 스레드만 소유할 수 있습니다. 둘째, 세마포어는 소유자가 없습니다.
   즉, 한 스레드가 세마포어를 "down"하고 다른 스레드가 "up"할 수 있지만,
   락의 경우 같은 스레드가 획득과 해제를 모두 해야 합니다. 이러한 제한이
   번거로울 때는 락 대신 세마포어를 사용해야 한다는 좋은 신호입니다. */
void lock_init(struct lock *lock)
{
    ASSERT(lock != NULL);

    lock->holder = NULL;
    sema_init(&lock->semaphore, 1);
}

/*
    project 1.3 priority_donate 를 위해 추가된 함수
    이 함수는 내가 필요한 lock을 가지고 있으면서, 나보다 낮은 우선순위를 가진
   쓰레드에게 자신이 가진 우선순위를 재귀적으로 기부합니다.
*/
void priority_donate(struct thread *curr, struct thread *holder)
{
    /* 우선순위를 기부받았는데 기다리는 락이 있을 경우 */
    if (holder->waiting_lock != NULL &&
        holder->waiting_lock->holder->priority < curr->priority)
    {
        holder->waiting_lock->holder->priority = curr->priority;
        priority_donate(curr, holder->waiting_lock->holder);
    }
}

/* LOCK을 획득합니다. 필요한 경우 사용 가능해질 때까지 슬립합니다.
   락은 현재 스레드가 이미 보유하고 있어서는 안 됩니다.

   이 함수는 슬립할 수 있으므로 인터럽트 핸들러 내에서 호출되어서는 안 됩니다.
   이 함수는 인터럽트가 비활성화된 상태에서 호출될 수 있지만, 슬립해야 하는
   경우 인터럽트가 다시 켜집니다. */
void lock_acquire(struct lock *lock)
{
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(!lock_held_by_current_thread(lock));

    /* project 1.3 priority_donation 을 위해 추가된 코드 */
    enum intr_level old_level = intr_disable();

    struct thread *curr = thread_current();
    /*
        누가 락을 들고 있으면 내가 어떤 락을 기다리는지 체크
        추후 thread_set_priority 가 일어났을 때, 변경해주기 위해서
    */

    if (lock->holder != NULL)
    {
        curr->waiting_lock = lock;

        /* 내 priority 가 더 높은 경우만 기부를 한다. */
        if (lock->holder->priority < curr->priority)
        {
            lock->holder->priority = curr->priority;
            list_push_front(&lock->holder->donation_list, &curr->donation_elem);

            /* TODO: holder의 donate_list에 넣어줄 함수 */
            priority_donate(curr, lock->holder);
        }
    }

    intr_set_level(old_level);

    sema_down(&lock->semaphore);
    lock->holder = thread_current();
}

/* LOCK을 획득하려고 시도하고 성공하면 true를, 실패하면 false를 반환합니다.
   락은 현재 스레드가 이미 보유하고 있어서는 안 됩니다.

   이 함수는 슬립하지 않으므로 인터럽트 핸들러 내에서 호출될 수 있습니다. */
bool lock_try_acquire(struct lock *lock)
{
    bool success;

    ASSERT(lock != NULL);
    ASSERT(!lock_held_by_current_thread(lock));

    success = sema_try_down(&lock->semaphore);
    if (success) lock->holder = thread_current();
    return success;
}

/* 현재 스레드가 소유해야 하는 LOCK을 해제합니다.
   이것은 lock_release 함수입니다.

   인터럽트 핸들러는 락을 획득할 수 없으므로, 인터럽트 핸들러 내에서
   락을 해제하려고 시도하는 것은 의미가 없습니다. */
void lock_release(struct lock *lock)
{
    ASSERT(lock != NULL);
    ASSERT(lock_held_by_current_thread(lock));

    /* proect 1.3 priority_donation 을 위해 추가된 코드 */
    enum intr_level old_level = intr_disable();

    /* 1. lock을 해제하면서 donation_list에서 해당 lock 을 기다리는 쓰레드 제거
     */
    struct list_elem *e = list_begin(&lock->holder->donation_list);
    while (e != list_end(&lock->holder->donation_list))
    {
        struct list_elem *next = list_next(e);
        struct thread *curr = list_entry(e, struct thread, donation_elem);

        if (lock == curr->waiting_lock)
        {
            curr->waiting_lock = NULL;
            list_remove(e);
        }

        e = next;
    }

    /* 2. 아직 donation_list 에 무언가 남아있으면 가장 큰 값을 priority 로
     * 설정*/
    lock->holder->priority = thread_max_priority(lock->holder);
    lock->holder = NULL;

    intr_set_level(old_level);

    sema_up(&lock->semaphore);
}

/* 현재 스레드가 LOCK을 보유하고 있으면 true를, 그렇지 않으면 false를
   반환합니다. (다른 스레드가 락을 보유하고 있는지 테스트하는 것은 경쟁 조건이
   될 수 있습니다.) */
bool lock_held_by_current_thread(const struct lock *lock)
{
    ASSERT(lock != NULL);

    return lock->holder == thread_current();
}

/* 리스트의 하나의 세마포어입니다. */
struct semaphore_elem
{
    struct list_elem elem;      /* 리스트 요소입니다. */
    struct semaphore semaphore; /* 이 세마포어입니다. */
    int priority; /* semaphore_elem 이 가지는 우선순위 입니다. */
};

/* 조건 변수 COND를 초기화합니다. 조건 변수는 한 코드 조각이 조건을 신호하고
   협력하는 코드가 신호를 받아 그에 따라 행동할 수 있게 해줍니다. */
void cond_init(struct condition *cond)
{
    ASSERT(cond != NULL);

    list_init(&cond->waiters);
}

/*
    condition 구조체의 waiter list를 우선순위로 정렬하기 위한 less 함수입니다.
*/
bool cmp_cond_priority(const struct list_elem *a, const struct list_elem *b,
                       void *aux)
{
    int new_priority = list_entry(a, struct semaphore_elem, elem)->priority;
    int list_priority = list_entry(b, struct semaphore_elem, elem)->priority;

    return new_priority > list_priority;
}

/* 원자적으로 LOCK을 해제하고 다른 코드 조각에 의해 COND가 신호될 때까지
   기다립니다. COND가 신호된 후, 반환하기 전에 LOCK을 다시 획득합니다. 이 함수를
   호출하기 전에 LOCK을 보유하고 있어야 합니다.

   이 함수에 의해 구현된 모니터는 "Hoare" 스타일이 아닌 "Mesa" 스타일입니다.
   즉, 신호를 보내고 받는 것이 원자적 연산이 아닙니다. 따라서 일반적으로
   호출자는 대기가 완료된 후 조건을 다시 확인해야 하며, 필요한 경우 다시
   대기해야 합니다.

   주어진 조건 변수는 하나의 락과만 연관되지만, 하나의 락은 여러 조건 변수와
   연관될 수 있습니다. 즉, 락에서 조건 변수로의 일대다 매핑이 있습니다.

   이 함수는 슬립할 수 있으므로 인터럽트 핸들러 내에서 호출되어서는 안 됩니다.
   이 함수는 인터럽트가 비활성화된 상태에서 호출될 수 있지만, 슬립해야 하는
   경우 인터럽트가 다시 켜집니다. */
void cond_wait(struct condition *cond, struct lock *lock)
{
    struct semaphore_elem waiter;

    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    sema_init(&waiter.semaphore, 0);

    waiter.priority = thread_current()->priority;
    // list_push_back (&cond->waiters, &waiter.elem);
    /* priority 1.3 을 구현하기 위해 변경된 함수 */
    list_insert_ordered(&cond->waiters, &waiter.elem, cmp_cond_priority, NULL);

    lock_release(lock);
    sema_down(&waiter.semaphore);
    lock_acquire(lock);
}

/* COND에서 대기 중인 스레드가 있다면 (LOCK으로 보호됨), 이 함수는 그 중
   하나에게 대기에서 깨어나도록 신호를 보냅니다. 이 함수를 호출하기 전에 LOCK을
   보유하고 있어야 합니다.

   인터럽트 핸들러는 락을 획득할 수 없으므로, 인터럽트 핸들러 내에서
   조건 변수에 신호를 보내려고 시도하는 것은 의미가 없습니다. */
void cond_signal(struct condition *cond, struct lock *lock UNUSED)
{
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    if (!list_empty(&cond->waiters))
        sema_up(&list_entry(list_pop_front(&cond->waiters),
                            struct semaphore_elem, elem)
                     ->semaphore);
}

/* COND에서 대기 중인 모든 스레드를 깨웁니다 (LOCK으로 보호됨).
   이 함수를 호출하기 전에 LOCK을 보유하고 있어야 합니다.

   인터럽트 핸들러는 락을 획득할 수 없으므로, 인터럽트 핸들러 내에서
   조건 변수에 신호를 보내려고 시도하는 것은 의미가 없습니다. */
void cond_broadcast(struct condition *cond, struct lock *lock)
{
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);

    while (!list_empty(&cond->waiters)) cond_signal(cond, lock);
}
