#include "threads/mmu.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "intrinsic.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/thread.h"

static uint64_t *pgdir_walk(uint64_t *pdp, const uint64_t va, int create)
{
    int idx = PDX(va);
    if (pdp)
    {
        uint64_t *pte = (uint64_t *) pdp[idx];
        if (!((uint64_t) pte & PTE_P))
        {
            if (create)
            {
                uint64_t *new_page = palloc_get_page(PAL_ZERO);
                if (new_page)
                    pdp[idx] = vtop(new_page) | PTE_U | PTE_W | PTE_P;
                else
                    return NULL;
            }
            else
                return NULL;
        }
        return (uint64_t *) ptov(PTE_ADDR(pdp[idx]) + 8 * PTX(va));
    }
    return NULL;
}

static uint64_t *pdpe_walk(uint64_t *pdpe, const uint64_t va, int create)
{
    uint64_t *pte = NULL;
    int idx = PDPE(va);
    int allocated = 0;
    if (pdpe)
    {
        uint64_t *pde = (uint64_t *) pdpe[idx];
        if (!((uint64_t) pde & PTE_P))
        {
            if (create)
            {
                uint64_t *new_page = palloc_get_page(PAL_ZERO);
                if (new_page)
                {
                    pdpe[idx] = vtop(new_page) | PTE_U | PTE_W | PTE_P;
                    allocated = 1;
                }
                else
                    return NULL;
            }
            else
                return NULL;
        }
        pte = pgdir_walk(ptov(PTE_ADDR(pdpe[idx])), va, create);
    }
    if (pte == NULL && allocated)
    {
        palloc_free_page((void *) ptov(PTE_ADDR(pdpe[idx])));
        pdpe[idx] = 0;
    }
    return pte;
}

/* 페이지 맵 레벨 4(pml4)에서 가상 주소 VADDR에 대한 페이지 테이블 항목의 주소를
   반환합니다. PML4E가 VADDR에 대한 페이지 테이블을 가지고 있지 않으면 CREATE에
   따라 동작이 달라집니다. CREATE가 true이면 새로운 페이지 테이블이 생성되고 그
   안의 포인터가 반환됩니다. 그렇지 않으면 null 포인터가 반환됩니다. */
uint64_t *pml4e_walk(uint64_t *pml4e, const uint64_t va, int create)
{
    uint64_t *pte = NULL;
    int idx = PML4(va);
    int allocated = 0;
    if (pml4e)
    {
        uint64_t *pdpe = (uint64_t *) pml4e[idx];
        if (!((uint64_t) pdpe & PTE_P))
        {
            if (create)
            {
                uint64_t *new_page = palloc_get_page(PAL_ZERO);
                if (new_page)
                {
                    pml4e[idx] = vtop(new_page) | PTE_U | PTE_W | PTE_P;
                    allocated = 1;
                }
                else
                    return NULL;
            }
            else
                return NULL;
        }
        pte = pdpe_walk(ptov(PTE_ADDR(pml4e[idx])), va, create);
    }
    if (pte == NULL && allocated)
    {
        palloc_free_page((void *) ptov(PTE_ADDR(pml4e[idx])));
        pml4e[idx] = 0;
    }
    return pte;
}

/*
        새로운 Page Map Level 4 (PML4) 를 생성한다.
        이 새 PML4에는 커널 가상 주소에 대한 매핑만 있고,
        사용자 가상 주소에 대한 매핑은 없다.
        실패 시 NULL을 반환한다.
*/
uint64_t *pml4_create(void)
{
    /* page table: 가상 주소 -> 물리 주소 (4KB 할당 받음) */
    uint64_t *pml4 = palloc_get_page(0);
    if (pml4) memcpy(pml4, base_pml4, PGSIZE);
    return pml4;
}

static bool pt_for_each(uint64_t *pt, pte_for_each_func *func, void *aux,
                        unsigned pml4_index, unsigned pdp_index,
                        unsigned pdx_index)
{
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
    {
        uint64_t *pte = &pt[i];
        if (((uint64_t) *pte) & PTE_P)
        {
            void *va = (void *) (((uint64_t) pml4_index << PML4SHIFT) |
                                 ((uint64_t) pdp_index << PDPESHIFT) |
                                 ((uint64_t) pdx_index << PDXSHIFT) |
                                 ((uint64_t) i << PTXSHIFT));
            if (!func(pte, va, aux)) return false;
        }
    }
    return true;
}

static bool pgdir_for_each(uint64_t *pdp, pte_for_each_func *func, void *aux,
                           unsigned pml4_index, unsigned pdp_index)
{
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
    {
        uint64_t *pte = ptov((uint64_t *) pdp[i]);
        if (((uint64_t) pte) & PTE_P)
            if (!pt_for_each((uint64_t *) PTE_ADDR(pte), func, aux, pml4_index,
                             pdp_index, i))
                return false;
    }
    return true;
}

static bool pdp_for_each(uint64_t *pdp, pte_for_each_func *func, void *aux,
                         unsigned pml4_index)
{
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
    {
        uint64_t *pde = ptov((uint64_t *) pdp[i]);
        if (((uint64_t) pde) & PTE_P)
            if (!pgdir_for_each((uint64_t *) PTE_ADDR(pde), func, aux,
                                pml4_index, i))
                return false;
    }
    return true;
}

/* 커널 것을 포함하여 사용 가능한 각 pte 항목에 FUNC를 적용합니다. */
bool pml4_for_each(uint64_t *pml4, pte_for_each_func *func, void *aux)
{
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
    {
        uint64_t *pdpe = ptov((uint64_t *) pml4[i]);
        if (((uint64_t) pdpe) & PTE_P)
            if (!pdp_for_each((uint64_t *) PTE_ADDR(pdpe), func, aux, i))
                return false;
    }
    return true;
}

static void pt_destroy(uint64_t *pt)
{
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
    {
        uint64_t *pte = ptov((uint64_t *) pt[i]);
        if (((uint64_t) pte) & PTE_P) palloc_free_page((void *) PTE_ADDR(pte));
    }
    palloc_free_page((void *) pt);
}

static void pgdir_destroy(uint64_t *pdp)
{
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
    {
        uint64_t *pte = ptov((uint64_t *) pdp[i]);
        if (((uint64_t) pte) & PTE_P) pt_destroy(PTE_ADDR(pte));
    }
    palloc_free_page((void *) pdp);
}

static void pdpe_destroy(uint64_t *pdpe)
{
    for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++)
    {
        uint64_t *pde = ptov((uint64_t *) pdpe[i]);
        if (((uint64_t) pde) & PTE_P) pgdir_destroy((void *) PTE_ADDR(pde));
    }
    palloc_free_page((void *) pdpe);
}

/* pml4e를 파괴하고 그것이 참조하는 모든 페이지를 해제합니다. */
void pml4_destroy(uint64_t *pml4)
{
    if (pml4 == NULL) return;
    ASSERT(pml4 != base_pml4);

    /* PML4 (vaddr) >= 1이면 정의상 커널 공간입니다. */
    uint64_t *pdpe = ptov((uint64_t *) pml4[0]);
    if (((uint64_t) pdpe) & PTE_P) pdpe_destroy((void *) PTE_ADDR(pdpe));
    palloc_free_page((void *) pml4);
}

/* 페이지 디렉터리 PD를 CPU의 페이지 디렉터리 베이스 레지스터에 로드합니다. */
void pml4_activate(uint64_t *pml4)
{
    lcr3(vtop(pml4 ? pml4 : base_pml4));
}

/* pml4에서 사용자 가상 주소 UADDR에 해당하는 물리 주소를 찾습니다.
   그 물리 주소에 해당하는 커널 가상 주소를 반환하거나,
   UADDR이 매핑되지 않았으면 null 포인터를 반환합니다. */
void *pml4_get_page(uint64_t *pml4, const void *uaddr)
{
    ASSERT(is_user_vaddr(uaddr));

    uint64_t *pte = pml4e_walk(pml4, (uint64_t) uaddr, 0);

    if (pte && (*pte & PTE_P)) return ptov(PTE_ADDR(*pte)) + pg_ofs(uaddr);
    return NULL;
}

/* 페이지 맵 레벨 4 PML4에서 사용자 가상 페이지 UPAGE에서
   커널 가상 주소 KPAGE로 식별되는 물리 프레임으로의 매핑을 추가합니다.
   UPAGE는 이미 매핑되어 있으면 안 됩니다. KPAGE는 아마도 palloc_get_page()로
   사용자 풀에서 얻은 페이지여야 합니다.
   WRITABLE이 true이면 새 페이지는 읽기/쓰기가 가능하고,
   그렇지 않으면 읽기 전용입니다.
   성공하면 true를, 메모리 할당이 실패하면 false를 반환합니다. */
bool pml4_set_page(uint64_t *pml4, void *upage, void *kpage, bool rw)
{
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(pg_ofs(kpage) == 0);
    ASSERT(is_user_vaddr(upage));
    ASSERT(pml4 != base_pml4);

    uint64_t *pte = pml4e_walk(pml4, (uint64_t) upage, 1);

    if (pte) *pte = vtop(kpage) | PTE_P | (rw ? PTE_W : 0) | PTE_U;
    return pte != NULL;
}

/* 페이지 디렉터리 PD에서 사용자 가상 페이지 UPAGE를 "존재하지 않음"으로
   표시합니다. 이후 페이지에 대한 접근은 페이지 폴트를 발생시킵니다. 페이지
   테이블 항목의 다른 비트들은 보존됩니다. UPAGE는 매핑되어 있을 필요가
   없습니다. */
void pml4_clear_page(uint64_t *pml4, void *upage)
{
    uint64_t *pte;
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(is_user_vaddr(upage));

    pte = pml4e_walk(pml4, (uint64_t) upage, false);

    if (pte != NULL && (*pte & PTE_P) != 0)
    {
        *pte &= ~PTE_P;
        if (rcr3() == vtop(pml4)) invlpg((uint64_t) upage);
    }
}

/* PML4의 가상 페이지 VPAGE에 대한 PTE가 더티인지, 즉 PTE가 설치된 이후로
   페이지가 수정되었는지 반환합니다.
   PML4가 VPAGE에 대한 PTE를 포함하지 않으면 false를 반환합니다. */
bool pml4_is_dirty(uint64_t *pml4, const void *vpage)
{
    uint64_t *pte = pml4e_walk(pml4, (uint64_t) vpage, false);
    return pte != NULL && (*pte & PTE_D) != 0;
}

/* PML4의 가상 페이지 VPAGE에 대한 PTE에서 더티 비트를 DIRTY로 설정합니다. */
void pml4_set_dirty(uint64_t *pml4, const void *vpage, bool dirty)
{
    uint64_t *pte = pml4e_walk(pml4, (uint64_t) vpage, false);
    if (pte)
    {
        if (dirty)
            *pte |= PTE_D;
        else
            *pte &= ~(uint32_t) PTE_D;

        if (rcr3() == vtop(pml4)) invlpg((uint64_t) vpage);
    }
}

/* PML4의 가상 페이지 VPAGE에 대한 PTE가 최근에 접근되었는지,
   즉 PTE가 설치된 시점과 마지막으로 클리어된 시점 사이에 접근되었는지
   반환합니다. PML4가 VPAGE에 대한 PTE를 포함하지 않으면 false를 반환합니다. */
bool pml4_is_accessed(uint64_t *pml4, const void *vpage)
{
    uint64_t *pte = pml4e_walk(pml4, (uint64_t) vpage, false);
    return pte != NULL && (*pte & PTE_A) != 0;
}

/* PD의 가상 페이지 VPAGE에 대한 PTE에서 접근 비트를 ACCESSED로 설정합니다. */
void pml4_set_accessed(uint64_t *pml4, const void *vpage, bool accessed)
{
    uint64_t *pte = pml4e_walk(pml4, (uint64_t) vpage, false);
    if (pte)
    {
        if (accessed)
            *pte |= PTE_A;
        else
            *pte &= ~(uint32_t) PTE_A;

        if (rcr3() == vtop(pml4)) invlpg((uint64_t) vpage);
    }
}
