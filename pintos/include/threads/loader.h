#ifndef THREADS_LOADER_H
#define THREADS_LOADER_H

/* PC BIOS에 의해 고정된 상수들 */
#define LOADER_BASE 0x7c00 /* 로더 베이스의 물리 주소 */
#define LOADER_END 0x7e00  /* 로더 끝의 물리 주소 */

/* 커널 베이스의 물리 주소 */
#define LOADER_KERN_BASE 0x8004000000

/* 모든 물리 메모리가 매핑되는 커널 가상 주소 */
#define LOADER_PHYS_BASE 0x200000

/* 멀티부트 정보 */
#define MULTIBOOT_INFO 0x7000
#define MULTIBOOT_FLAG MULTIBOOT_INFO
#define MULTIBOOT_MMAP_LEN MULTIBOOT_INFO + 44
#define MULTIBOOT_MMAP_ADDR MULTIBOOT_INFO + 48

#define E820_MAP MULTIBOOT_INFO + 52
#define E820_MAP4 MULTIBOOT_INFO + 56

/* 중요한 로더 물리 주소들 */
#define LOADER_SIG (LOADER_END - LOADER_SIG_LEN)   /* 0xaa55 BIOS 서명 */
#define LOADER_ARGS (LOADER_SIG - LOADER_ARGS_LEN) /* 명령줄 인수들 */
#define LOADER_ARG_CNT (LOADER_ARGS - LOADER_ARG_CNT_LEN) /* 인수 개수 */

/* 로더 데이터 구조의 크기들 */
#define LOADER_SIG_LEN 2
#define LOADER_ARGS_LEN 128
#define LOADER_ARG_CNT_LEN 4

/* 로더에 의해 정의된 GDT 선택자들.
   더 많은 선택자들은 userprog/gdt.h에 정의되어 있습니다. */
#define SEL_NULL 0x00  /* 널 선택자 */
#define SEL_KCSEG 0x08 /* 커널 코드 선택자 */
#define SEL_KDSEG 0x10 /* 커널 데이터 선택자 */
#define SEL_UDSEG 0x1B /* 사용자 데이터 선택자 */
#define SEL_UCSEG 0x23 /* 사용자 코드 선택자 */
#define SEL_TSS 0x28   /* 태스크 상태 세그먼트 */
#define SEL_CNT 8      /* 세그먼트 개수 */

#endif /* threads/loader.h */
