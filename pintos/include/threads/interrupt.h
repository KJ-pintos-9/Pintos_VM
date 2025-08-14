#ifndef THREADS_INTERRUPT_H
#define THREADS_INTERRUPT_H

#include <stdbool.h>
#include <stdint.h>

/* Interrupts on or off? */
enum intr_level
{
    INTR_OFF, /* Interrupts disabled. */
    INTR_ON   /* Interrupts enabled. */
};

enum intr_level intr_get_level(void);
enum intr_level intr_set_level(enum intr_level);
enum intr_level intr_enable(void);
enum intr_level intr_disable(void);

/* Interrupt stack frame. */
struct gp_registers
{
    uint64_t r15; /* Caller saved */
    uint64_t r14; /* Caller saved */
    uint64_t r13; /* Caller saved */
    uint64_t r12; /* Caller saved */
    uint64_t r11; /* Caller saved */
    uint64_t r10; /* Caller saved */
    uint64_t r9;  /* 6th argument	*/
    uint64_t r8;  /* 5th argument */
    uint64_t rsi; /* 2nd argument: argv */
    uint64_t rdi; /* 1st argument: argc */
    uint64_t rbp; /* Callee saved (함수 주소) */
    uint64_t rdx; /* 3rd argument */
    uint64_t rcx; /* 4th argument */
    uint64_t rbx; /* Callee saved (복원 레지스터) */
    uint64_t rax; /* Return value */
} __attribute__((packed));

struct intr_frame
{
    /* intr-stubs.S의 intr_entry에 의해 스택에 푸시됨.
       인터럽트가 발생한 작업의 저장된 레지스터들 */
    struct gp_registers R;
    uint16_t es; /* 확장 세그먼트 레지스터 (Extra Segment register) */
    uint16_t pad1; /* 패딩 (메모리 정렬을 위한 공간) */
    uint32_t pad2; /* 패딩 (메모리 정렬을 위한 공간) */
    uint16_t ds; /* 데이터 세그먼트 레지스터 (Data Segment register) */
    uint16_t pad3; /* 패딩 (메모리 정렬을 위한 공간) */
    uint32_t pad4; /* 패딩 (메모리 정렬을 위한 공간) */
    /* intr-stubs.S의 intrNN_stub에 의해 푸시됨 */
    uint64_t vec_no; /* 인터럽트 벡터 번호 (어떤 인터럽트인지 식별) */
    /* CPU에 의해 때때로 푸시되며, 일관성을 위해 intrNN_stub에서 0으로 푸시됨.
       CPU는 이를 `eip` 바로 아래에 두지만, 우리는 여기로 이동시킴 */
    uint64_t error_code; /* 에러 코드 (인터럽트 발생 시 추가 정보) */

    uintptr_t
        rip; /* 명령어 포인터 (Instruction Pointer - 다음 실행할 명령어 주소) */
    uint16_t cs; /* 코드 세그먼트 레지스터 (Code Segment register) */
    uint16_t __pad5; /* 패딩 (메모리 정렬을 위한 공간) */
    uint32_t __pad6; /* 패딩 (메모리 정렬을 위한 공간) */
    uint64_t eflags; /* 플래그 레지스터 (프로세서 상태 플래그들) */
    uintptr_t rsp; /* 스택 포인터 (Stack Pointer - 현재 스택의 최상단 주소) */
    uint16_t ss; /* 스택 세그먼트 레지스터 (Stack Segment register) */
    uint16_t __pad7; /* 패딩 (메모리 정렬을 위한 공간) */
    uint32_t __pad8; /* 패딩 (메모리 정렬을 위한 공간) */
} __attribute__((packed));

typedef void intr_handler_func(struct intr_frame *);

void intr_init(void);
void intr_register_ext(uint8_t vec, intr_handler_func *, const char *name);
void intr_register_int(uint8_t vec, int dpl, enum intr_level,
                       intr_handler_func *, const char *name);
bool intr_context(void);
void intr_yield_on_return(void);

void intr_dump_frame(const struct intr_frame *);
const char *intr_name(uint8_t vec);

#endif /* threads/interrupt.h */
