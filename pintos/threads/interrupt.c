#include "threads/interrupt.h"

#include <debug.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "devices/timer.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/intr-stubs.h"
#include "threads/io.h"
#include "threads/mmu.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/gdt.h"
#endif

/* x86_64 인터럽트의 개수 */
#define INTR_CNT 256

/* FUNCTION을 호출하는 게이트를 생성합니다.

   게이트는 디스크립터 권한 레벨 DPL을 가지며, 이는 프로세서가 DPL 또는
   더 낮은 번호의 링에 있을 때 의도적으로 호출될 수 있음을 의미합니다.
   실제로 DPL==3은 사용자 모드에서 게이트를 호출할 수 있게 하고,
   DPL==0은 그러한 호출을 방지합니다. 사용자 모드에서 발생하는 오류와
   예외는 여전히 DPL==0인 게이트를 호출하게 됩니다.

   TYPE은 14(인터럽트 게이트) 또는 15(트랩 게이트) 중 하나여야 합니다.
   차이점은 인터럽트 게이트에 진입하면 인터럽트가 비활성화되지만,
   트랩 게이트에 진입할 때는 그렇지 않다는 것입니다. 자세한 내용은
   [IA32-v3a] 섹션 5.12.1.2 "예외 또는 인터럽트 핸들러 프로시저에 의한
   플래그 사용법"을 참조하십시오. */

struct gate
{
    unsigned off_15_0 : 16;  // 세그먼트 내 오프셋의 하위 16비트
    unsigned ss : 16;        // 세그먼트 선택자
    unsigned ist : 3;   // 인자 개수, 인터럽트/트랩 게이트는 0
    unsigned rsv1 : 5;  // 예약됨(0이어야 함)
    unsigned type : 4;  // 타입(STS_{TG,IG32,TG32})
    unsigned s : 1;     // 반드시 0이어야 함 (시스템)
    unsigned dpl : 2;   // 디스크립터(새로운) 권한 레벨
    unsigned p : 1;     // 존재함
    unsigned off_31_16 : 16;  // 세그먼트 내 오프셋의 상위 비트
    uint32_t off_32_63;
    uint32_t rsv2;
};

/* 인터럽트 디스크립터 테이블(IDT). 형식은 CPU에 의해 고정됩니다.
   [IA32-v3a] 섹션 5.10 "인터럽트 디스크립터 테이블(IDT)",
   5.11 "IDT 디스크립터", 5.12.1.2 "예외 또는 인터럽트 핸들러
   프로시저에 의한 플래그 사용법"을 참조하십시오. */
static struct gate idt[INTR_CNT];

static struct desc_ptr idt_desc = {.size = sizeof(idt) - 1,
                                   .address = (uint64_t) idt};

#define make_gate(g, function, d, t)                                 \
    {                                                                \
        ASSERT((function) != NULL);                                  \
        ASSERT((d) >= 0 && (d) <= 3);                                \
        ASSERT((t) >= 0 && (t) <= 15);                               \
        *(g) = (struct gate){                                        \
            .off_15_0 = (uint64_t) (function) &0xffff,               \
            .ss = SEL_KCSEG,                                         \
            .ist = 0,                                                \
            .rsv1 = 0,                                               \
            .type = (t),                                             \
            .s = 0,                                                  \
            .dpl = (d),                                              \
            .p = 1,                                                  \
            .off_31_16 = ((uint64_t) (function) >> 16) & 0xffff,     \
            .off_32_63 = ((uint64_t) (function) >> 32) & 0xffffffff, \
            .rsv2 = 0,                                               \
        };                                                           \
    }

/* 주어진 DPL로 FUNCTION을 호출하는 인터럽트 게이트를 생성합니다. */
#define make_intr_gate(g, function, dpl) make_gate((g), (function), (dpl), 14)

/* 주어진 DPL로 FUNCTION을 호출하는 트랩 게이트를 생성합니다. */
#define make_trap_gate(g, function, dpl) make_gate((g), (function), (dpl), 15)

/* 각 인터럽트에 대한 인터럽트 핸들러 함수들 */
static intr_handler_func *intr_handlers[INTR_CNT];

/* 디버깅 목적으로 각 인터럽트의 이름들 */
static const char *intr_names[INTR_CNT];

/* 외부 인터럽트는 타이머와 같이 CPU 외부의 장치에서 생성되는 것들입니다.
   외부 인터럽트는 인터럽트가 꺼진 상태에서 실행되므로, 절대 중첩되지 않고
   선점되지도 않습니다. 외부 인터럽트 핸들러는 잠들 수도 없지만,
   인터럽트가 반환되기 직전에 새로운 프로세스가 스케줄링되도록 요청하기 위해
   intr_yield_on_return()을 호출할 수 있습니다. */
static bool in_external_intr; /* 외부 인터럽트를 처리 중인가? */
static bool yield_on_return; /* 인터럽트 반환 시 양보해야 하는가? */

/* 프로그래머블 인터럽트 컨트롤러 도우미들 */
static void pic_init(void);
static void pic_end_of_interrupt(int irq);

/* 인터럽트 핸들러들 */
void intr_handler(struct intr_frame *args);

/* 현재 인터럽트 상태를 반환합니다. */
enum intr_level intr_get_level(void)
{
    uint64_t flags;

    /* 프로세서 스택에 플래그 레지스터를 푸시한 다음, 스택에서 값을 팝하여
       `flags`에 저장합니다. [IA32-v2b] "PUSHF"와 "POP" 그리고
       [IA32-v3a] 5.8.1 "마스킹 가능한 하드웨어 인터럽트 마스킹"을 참조하십시오.
     */
    asm volatile("pushfq; popq %0" : "=g"(flags));

    return flags & FLAG_IF ? INTR_ON : INTR_OFF;
}

/* LEVEL에 지정된 대로 인터럽트를 활성화하거나 비활성화하고
   이전 인터럽트 상태를 반환합니다. */
enum intr_level intr_set_level(enum intr_level level)
{
    return level == INTR_ON ? intr_enable() : intr_disable();
}

/* 인터럽트를 활성화하고 이전 인터럽트 상태를 반환합니다. */
enum intr_level intr_enable(void)
{
    enum intr_level old_level = intr_get_level();
    ASSERT(!intr_context());

    /* 인터럽트 플래그를 설정하여 인터럽트를 활성화합니다.

       [IA32-v2b] "STI"와 [IA32-v3a] 5.8.1 "마스킹 가능한 하드웨어
       인터럽트 마스킹"을 참조하십시오. */
    asm volatile("sti");

    return old_level;
}

/* 인터럽트를 비활성화하고 이전 인터럽트 상태를 반환합니다. */
enum intr_level intr_disable(void)
{
    enum intr_level old_level = intr_get_level();

    /* 인터럽트 플래그를 클리어하여 인터럽트를 비활성화합니다.
       [IA32-v2b] "CLI"와 [IA32-v3a] 5.8.1 "마스킹 가능한 하드웨어
       인터럽트 마스킹"을 참조하십시오. */
    asm volatile("cli" : : : "memory");

    return old_level;
}

/* 인터럽트 시스템을 초기화합니다. */
void intr_init(void)
{
    int i;

    /* 인터럽트 컨트롤러를 초기화합니다. */
    pic_init();

    /* IDT를 초기화합니다. */
    for (i = 0; i < INTR_CNT; i++)
    {
        make_intr_gate(&idt[i], intr_stubs[i], 0);
        intr_names[i] = "unknown";
    }

#ifdef USERPROG
    /* TSS를 로드합니다. */
    ltr(SEL_TSS);
#endif

    /* IDT 레지스터를 로드합니다. */
    lidt(&idt_desc);

    /* intr_names를 초기화합니다. */
    intr_names[0] = "#DE Divide Error";
    intr_names[1] = "#DB Debug Exception";
    intr_names[2] = "NMI Interrupt";
    intr_names[3] = "#BP Breakpoint Exception";
    intr_names[4] = "#OF Overflow Exception";
    intr_names[5] = "#BR BOUND Range Exceeded Exception";
    intr_names[6] = "#UD Invalid Opcode Exception";
    intr_names[7] = "#NM Device Not Available Exception";
    intr_names[8] = "#DF Double Fault Exception";
    intr_names[9] = "Coprocessor Segment Overrun";
    intr_names[10] = "#TS Invalid TSS Exception";
    intr_names[11] = "#NP Segment Not Present";
    intr_names[12] = "#SS Stack Fault Exception";
    intr_names[13] = "#GP General Protection Exception";
    intr_names[14] = "#PF Page-Fault Exception";
    intr_names[16] = "#MF x87 FPU Floating-Point Error";
    intr_names[17] = "#AC Alignment Check Exception";
    intr_names[18] = "#MC Machine-Check Exception";
    intr_names[19] = "#XF SIMD Floating-Point Exception";
}

/* 인터럽트 VEC_NO를 등록하여 디스크립터 권한 레벨 DPL로 HANDLER를 호출합니다.
   디버깅 목적으로 인터럽트의 이름을 NAME으로 지정합니다. 인터럽트 핸들러는
   인터럽트 상태가 LEVEL로 설정된 상태에서 호출됩니다. */
static void register_handler(uint8_t vec_no, int dpl, enum intr_level level,
                             intr_handler_func *handler, const char *name)
{
    ASSERT(intr_handlers[vec_no] == NULL);
    if (level == INTR_ON)
    {
        make_trap_gate(&idt[vec_no], intr_stubs[vec_no], dpl);
    }
    else
    {
        make_intr_gate(&idt[vec_no], intr_stubs[vec_no], dpl);
    }
    intr_handlers[vec_no] = handler;
    intr_names[vec_no] = name;
}

/* 외부 인터럽트 VEC_NO를 등록하여 HANDLER를 호출합니다. 디버깅 목적으로
   NAME으로 이름을 지정합니다. 핸들러는 인터럽트가 비활성화된 상태에서
   실행됩니다. */
void intr_register_ext(uint8_t vec_no, intr_handler_func *handler,
                       const char *name)
{
    ASSERT(vec_no >= 0x20 && vec_no <= 0x2f);
    register_handler(vec_no, 0, INTR_OFF, handler, name);
}

/* 내부 인터럽트 VEC_NO를 등록하여 HANDLER를 호출합니다. 디버깅 목적으로
   NAME으로 이름을 지정합니다. 인터럽트 핸들러는 인터럽트 상태가 LEVEL로
   설정된 상태에서 호출됩니다.

   핸들러는 디스크립터 권한 레벨 DPL을 가지며, 이는 프로세서가 DPL 또는
   더 낮은 번호의 링에 있을 때 의도적으로 호출될 수 있음을 의미합니다.
   실제로 DPL==3은 사용자 모드에서 인터럽트를 호출할 수 있게 하고
   DPL==0은 그러한 호출을 방지합니다. 사용자 모드에서 발생하는 오류와
   예외는 여전히 DPL==0인 인터럽트를 호출하게 됩니다. 자세한 내용은
   [IA32-v3a] 섹션 4.5 "권한 레벨"과 4.8.1.1 "비준수 코드 세그먼트 접근"을
   참조하십시오. */
void intr_register_int(uint8_t vec_no, int dpl, enum intr_level level,
                       intr_handler_func *handler, const char *name)
{
    ASSERT(vec_no < 0x20 || vec_no > 0x2f);
    register_handler(vec_no, dpl, level, handler, name);
}

/* 외부 인터럽트 처리 중에는 true를 반환하고 다른 모든 시간에는 false를
 * 반환합니다. */
bool intr_context(void)
{
    return in_external_intr;
}

/* 외부 인터럽트 처리 중에, 인터럽트에서 반환하기 직전에 새로운 프로세스로
   양보하도록 인터럽트 핸들러에 지시합니다. 다른 시간에는 호출할 수 없습니다. */
void intr_yield_on_return(void)
{
    ASSERT(intr_context());
    yield_on_return = true;
}

/* 8259A 프로그래머블 인터럽트 컨트롤러 */

/* 모든 PC는 두 개의 8259A 프로그래머블 인터럽트 컨트롤러(PIC) 칩을 가집니다.
   하나는 포트 0x20과 0x21에서 접근 가능한 "마스터"입니다.
   다른 하나는 마스터의 IRQ 2 라인에 연결된 "슬레이브"로 포트 0xa0과 0xa1에서
   접근 가능합니다. 포트 0x20에 대한 접근은 A0 라인을 0으로 설정하고
   0x21에 대한 접근은 A1 라인을 1로 설정합니다. 슬레이브 PIC도 상황이
   비슷합니다.

   기본적으로 PIC에서 전달되는 인터럽트 0...15는 인터럽트 벡터 0...15로 갑니다.
   불행히도 이 벡터들은 CPU 트랩과 예외에도 사용됩니다. 우리는 PIC를 다시
   프로그래밍하여 인터럽트 0...15가 대신 인터럽트 벡터 32...47 (0x20...0x2f)로
   전달되도록 합니다. */

/* PIC들을 초기화합니다. 자세한 내용은 [8259A]를 참조하십시오. */
static void pic_init(void)
{
    /* 두 PIC 모두에서 모든 인터럽트를 마스킹합니다. */
    outb(0x21, 0xff);
    outb(0xa1, 0xff);

    /* 마스터를 초기화합니다. */
    outb(0x20, 0x11); /* ICW1: 단일 모드, 에지 트리거, ICW4 기대 */
    outb(0x21, 0x20); /* ICW2: 라인 IR0...7 -> irq 0x20...0x27 */
    outb(0x21, 0x04); /* ICW3: 라인 IR2에 슬레이브 PIC */
    outb(0x21, 0x01); /* ICW4: 8086 모드, 일반 EOI, 비버퍼링 */

    /* 슬레이브를 초기화합니다. */
    outb(0xa0, 0x11); /* ICW1: 단일 모드, 에지 트리거, ICW4 기대 */
    outb(0xa1, 0x28); /* ICW2: 라인 IR0...7 -> irq 0x28...0x2f */
    outb(0xa1, 0x02); /* ICW3: 슬레이브 ID는 2 */
    outb(0xa1, 0x01); /* ICW4: 8086 모드, 일반 EOI, 비버퍼링 */

    /* 모든 인터럽트를 언마스킹합니다. */
    outb(0x21, 0x00);
    outb(0xa1, 0x00);
}

/* 주어진 IRQ에 대해 PIC에 인터럽트 종료 신호를 보냅니다.
   IRQ를 확인하지 않으면 다시는 전달되지 않으므로 이것은 중요합니다. */
static void pic_end_of_interrupt(int irq)
{
    ASSERT(irq >= 0x20 && irq < 0x30);

    /* 마스터 PIC를 확인합니다. */
    outb(0x20, 0x20);

    /* 슬레이브 인터럽트인 경우 슬레이브 PIC를 확인합니다. */
    if (irq >= 0x28) outb(0xa0, 0x20);
}
/* 인터럽트 핸들러들 */

/* 모든 인터럽트, 오류, 예외에 대한 핸들러입니다. 이 함수는
   intr-stubs.S의 어셈블리 언어 인터럽트 스텁에 의해 호출됩니다.
   FRAME은 인터럽트와 중단된 스레드의 레지스터를 설명합니다. */
void intr_handler(struct intr_frame *frame)
{
    bool external;
    intr_handler_func *handler;

    /* 외부 인터럽트는 특별합니다.
       한 번에 하나씩만 처리하고(따라서 인터럽트는 꺼져 있어야 함)
       PIC에서 확인되어야 합니다(아래 참조).
       외부 인터럽트 핸들러는 잠들 수 없습니다. */
    external = frame->vec_no >= 0x20 && frame->vec_no < 0x30;
    if (external)
    {
        ASSERT(intr_get_level() == INTR_OFF);
        ASSERT(!intr_context());

        in_external_intr = true;
        yield_on_return = false;
    }

    /* 인터럽트의 핸들러를 호출합니다. */
    handler = intr_handlers[frame->vec_no];
    if (handler != NULL)
        handler(frame);
    else if (frame->vec_no == 0x27 || frame->vec_no == 0x2f)
    {
        /* 핸들러가 없지만, 이 인터럽트는 하드웨어 오류나 하드웨어 경쟁 상태로
           인해 가짜로 트리거될 수 있습니다. 무시합니다. */
    }
    else
    {
        /* 핸들러가 없고 가짜도 아닙니다. 예상치 못한 인터럽트 핸들러를
         * 호출합니다. */
        intr_dump_frame(frame);
        PANIC("Unexpected interrupt");
    }

    /* 외부 인터럽트 처리를 완료합니다. */
    if (external)
    {
        ASSERT(intr_get_level() == INTR_OFF);
        ASSERT(intr_context());

        in_external_intr = false;
        pic_end_of_interrupt(frame->vec_no);

        if (yield_on_return) thread_yield();
    }
}

/* 디버깅을 위해 인터럽트 프레임 F를 콘솔에 덤프합니다. */
void intr_dump_frame(const struct intr_frame *f)
{
    /* CR2는 마지막 페이지 오류의 선형 주소입니다.
       [IA32-v2a] "MOV--제어 레지스터로/에서 이동"과
       [IA32-v3a] 5.14 "인터럽트 14--페이지 오류 예외(#PF)"를 참조하십시오. */
    uint64_t cr2 = rcr2();
    printf("Interrupt %#04llx (%s) at rip=%llx\n", f->vec_no,
           intr_names[f->vec_no], f->rip);
    printf(" cr2=%016llx error=%16llx\n", cr2, f->error_code);
    printf("rax %016llx rbx %016llx rcx %016llx rdx %016llx\n", f->R.rax,
           f->R.rbx, f->R.rcx, f->R.rdx);
    printf("rsp %016llx rbp %016llx rsi %016llx rdi %016llx\n", f->rsp,
           f->R.rbp, f->R.rsi, f->R.rdi);
    printf("rip %016llx r8 %016llx  r9 %016llx r10 %016llx\n", f->rip, f->R.r8,
           f->R.r9, f->R.r10);
    printf("r11 %016llx r12 %016llx r13 %016llx r14 %016llx\n", f->R.r11,
           f->R.r12, f->R.r13, f->R.r14);
    printf("r15 %016llx rflags %08llx\n", f->R.r15, f->eflags);
    printf("es: %04x ds: %04x cs: %04x ss: %04x\n", f->es, f->ds, f->cs, f->ss);
}

/* 인터럽트 VEC의 이름을 반환합니다. */
const char *intr_name(uint8_t vec)
{
    return intr_names[vec];
}
