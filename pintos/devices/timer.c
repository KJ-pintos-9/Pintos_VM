#include "devices/timer.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdint.h>
#include <stdio.h>

#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* 8254 타이머 칩의 하드웨어 세부사항은 [8254]를 참조하세요. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* OS 부팅 이후 타이머 틱 수 */
static int64_t ticks;

/* 타이머 틱당 루프 수
   timer_calibrate()에 의해 초기화됨 */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops(unsigned loops);
static void busy_wait(int64_t loops);
static void real_time_sleep(int64_t num, int32_t denom);

/* 8254 프로그래머블 인터벌 타이머(PIT)를 설정하여
   초당 PIT_FREQ 횟수만큼 인터럽트를 발생시키고,
   해당 인터럽트를 등록합니다. */
void timer_init(void)
{
    /* 8254 입력 주파수를 TIMER_FREQ로 나누고 반올림 */
    // count = 11932
    uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

    outb(0x43, 0x34); /* CW: counter 0, LSB then MSB, mode 2, binary. */
    outb(0x40, count & 0xff);
    outb(0x40, count >> 8);

    intr_register_ext(0x20, timer_interrupt, "8254 Timer");
}

/* 짧은 지연을 구현하는 데 사용되는 loops_per_tick을 보정합니다. */
void timer_calibrate(void)
{
    unsigned high_bit, test_bit;

    // 인터럽트가 ON 이 아니면 ERROR
    ASSERT(intr_get_level() == INTR_ON);
    printf("Calibrating timer...  ");

    /* loops_per_tick 을 1024로 변환합니다.
     * 1u는 unsigned int 형 입니다.
     * loops_per_tick 을 2의 거듭제곱으로 늘려가면서
     * 1 타이머 틱에 ( 1/100초 ) 루프를 몇 번 돌릴 수 있나 확인합니다.
     * 우린 TIMER_FREQ를 100으로 설정했으므로 1 타이머틱은 ( 1/100초 )가 됩니다.
     */
    loops_per_tick = 1u << 10;

    /* 틱당 최대 몇 루프를 도는지 체크한다. */
    while (!too_many_loops(loops_per_tick << 1))
    {
        loops_per_tick <<= 1;
        ASSERT(loops_per_tick != 0);
    }

    /* loops_per_tic 의 >> 1 부터 시작해서
     * loops_per_tic 의 >> 10 까지 즉 8번
     */
    high_bit = loops_per_tick;
    for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
        if (!too_many_loops(high_bit | test_bit)) loops_per_tick |= test_bit;

    printf("%'" PRIu64 " loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* 현재 타이머 틱 수를 반환합니다. */
/* 타이머 틱 수를 받아서 반환되는 동안 변하지 않게 인터럽트를 끄고 배리어로
 * 컴파일러에게 경고합니다. */
int64_t timer_ticks(void)
{
    enum intr_level old_level = intr_disable();
    int64_t t = ticks;
    intr_set_level(old_level);
    barrier();
    return t;
}

/* THEN 이후 경과된 타이머 틱 수를 반환합니다.
   THEN은 timer_ticks()에서 반환된 값이어야 합니다. */
/* 현재 타이머 틱에서 저장된 타이머 틱수를 뺀 값을 반환합니다. */
int64_t timer_elapsed(int64_t then)
{
    return timer_ticks() - then;
}

/* 대략 TICKS 타이머 틱 동안 실행을 일시 중지합니다. */
/* 타이머 틱에 대한 실행을 일시 중지합니다. */
void timer_sleep(int64_t ticks)
{
    ASSERT(intr_get_level() == INTR_ON);

    if (ticks == 0) return;

    /* project 1.1 alarm 의 busy_waiting 을 해결하기 위한 thread_sleep */
    thread_sleep(timer_ticks() + ticks);
}

/* 대략 MS 밀리초 동안 실행을 일시 중지합니다. */
void timer_msleep(int64_t ms)
{
    real_time_sleep(ms, 1000);
}

/* 대략 US 마이크로초 동안 실행을 일시 중지합니다. */
void timer_usleep(int64_t us)
{
    real_time_sleep(us, 1000 * 1000);
}

/* 대략 NS 나노초 동안 실행을 일시 중지합니다. */
void timer_nsleep(int64_t ns)
{
    real_time_sleep(ns, 1000 * 1000 * 1000);
}

/* 타이머 통계를 출력합니다. */
void timer_print_stats(void)
{
    printf("Timer: %" PRId64 " ticks\n", timer_ticks());
}

/* 타이머 인터럽트 핸들러 */
static void timer_interrupt(struct intr_frame *args UNUSED)
{
    ticks++;

    /* project 1.1 alarm으로 쓰레드를 wake up 시키기 위한 함수 */
    if (get_minimum_tick() <= ticks)
    {
        thread_wakeup();
    }

    thread_tick();
}

/* LOOPS 반복이 하나 이상의 타이머 틱보다 오래 기다리면 true를 반환하고,
   그렇지 않으면 false를 반환합니다. */
static bool too_many_loops(unsigned loops)
{
    /* 1. 현재 tick 정보를 저장*/
    int64_t start = ticks;

    /* 2. tick 변할때까지 대기 후 barrier 실행 */
    while (ticks == start) barrier();

    /* 3. 현재 틱을 다시 저장 */
    start = ticks;

    /* 4. 매개변수 loops 의 횟수만큼 바쁜루프 실행 */
    busy_wait(loops);

    /* 5. 틱이 바뀌었는지 확인하는 return */
    barrier();  // <-- 두번째 배리어 실행
    return start != ticks;
}

/* 짧은 지연을 구현하기 위해 간단한 루프를 LOOPS 횟수만큼 반복합니다.

   코드 정렬이 타이밍에 상당한 영향을 미칠 수 있으므로 NO_INLINE으로 표시되어
   있습니다. 이 함수가 다른 위치에서 다르게 인라인되면 결과를 예측하기
   어려워집니다. */
static void NO_INLINE busy_wait(int64_t loops)
{
    /* 1. loops가 0이 될 때까지 반복 */
    while (loops-- > 0) barrier();  // <-- 컴파일러가 바꾸지 않게 막기
}

/* 대략 NUM/DENOM 초 동안 대기합니다. */
static void real_time_sleep(int64_t num, int32_t denom)
{
    /* NUM/DENOM 초를 타이머 틱으로 변환하고 내림합니다.

       (NUM / DENOM) s
       ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
       1 s / TIMER_FREQ ticks
       */
    int64_t ticks = num * TIMER_FREQ / denom;

    ASSERT(intr_get_level() == INTR_ON);
    if (ticks > 0)
    {
        /* 최소 하나의 완전한 타이머 틱을 기다리고 있습니다.
           CPU를 다른 프로세스에게 양보하므로 timer_sleep()을 사용합니다. */
        timer_sleep(ticks);
    }
    else
    {
        /* 그렇지 않으면, 더 정확한 서브 틱 타이밍을 위해 바쁜 대기 루프를
           사용합니다. 오버플로우 가능성을 피하기 위해 분자와 분모를 1000으로
           나눕니다. */
        ASSERT(denom % 1000 == 0);
        busy_wait(loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
    }
}