#ifndef THREADS_PTE_H
#define THREADS_PTE_H

#include "threads/vaddr.h"

/* x86 하드웨어 페이지 테이블 작업을 위한 함수와 매크로들.
 * 가상 주소에 대한 더 일반적인 함수와 매크로는 vaddr.h를 참조하세요.
 *
 * 가상 주소는 다음과 같이 구조화됩니다:
 *  63          48 47            39 38            30 29            21 20 12 11 0
 * +-------------+----------------+----------------+----------------+-------------+------------+
 * | 부호 확장   |    페이지 맵    | 페이지 디렉터리 | 페이지 디렉터리 |  페이지
 * 테이블 |  물리적    | |             | 레벨-4 오프셋   |    포인터      |
 * 오프셋     |   오프셋    |   오프셋   |
 * +-------------+----------------+----------------+----------------+-------------+------------+
 *               |                |                |                | | |
 *               +------- 9 ------+------- 9 ------+------- 9 ------+----- 9
 * -----+---- 12 ----+ 가상 주소
 */

#define PML4SHIFT 39UL
#define PDPESHIFT 30UL
#define PDXSHIFT 21UL
#define PTXSHIFT 12UL

#define PML4(la) ((((uint64_t) (la)) >> PML4SHIFT) & 0x1FF)
#define PDPE(la) ((((uint64_t) (la)) >> PDPESHIFT) & 0x1FF)
#define PDX(la) ((((uint64_t) (la)) >> PDXSHIFT) & 0x1FF)
#define PTX(la) ((((uint64_t) (la)) >> PTXSHIFT) & 0x1FF)
#define PTE_ADDR(pte) ((uint64_t) (pte) & ~0xFFF)

/* 중요한 플래그들이 아래에 나열되어 있습니다.
   PDE나 PTE가 "present"가 아닐 때, 다른 플래그들은
   무시됩니다.
   0으로 초기화된 PDE나 PTE는 "not present"로 해석되며,
   이는 정상적인 동작입니다. */
#define PTE_FLAGS 0x00000000000000fffUL     /* 플래그 비트들 */
#define PTE_ADDR_MASK 0xffffffffffffff000UL /* 주소 비트들 */
#define PTE_AVL 0x00000e00 /* OS 사용을 위해 사용 가능한 비트들 */
#define PTE_P 0x1          /* 1=present, 0=not present */
#define PTE_W 0x2          /* 1=읽기/쓰기, 0=읽기 전용 */
#define PTE_U 0x4          /* 1=사용자/커널, 0=커널 전용 */
#define PTE_A 0x20         /* 1=접근됨, 0=접근되지 않음 */
#define PTE_D 0x40         /* 1=더티, 0=더티 아님 (PTE만 해당) */

#endif /* threads/pte.h */
