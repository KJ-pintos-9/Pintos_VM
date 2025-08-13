/* vm.c: Generic interface for virtual memory objects. */
/* vm.c: 가상 메모리 객체를 위한 일반적인 인터페이스. */

#include "vm/vm.h"
#include <hash.h>

#include "include/threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
/* 각 서브시스템의 초기화 코드를 호출하여 가상 메모리 서브시스템을 초기화합니다.
 */
struct list frame_table;
struct lock frame_table_lock;

void vm_init(void)
{
    vm_anon_init();
    vm_file_init();
    list_init(&frame_table);
    lock_init(&frame_table_lock);
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* 위 라인들을 수정하지 마십시오. */
    /* TODO: Your code goes here. */
    /* TODO: 여기에 코드를 작성하세요. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
/* 페이지의 타입을 가져옵니다. 이 함수는 페이지가 초기화된 후 그 타입을 알고
 * 싶을 때 유용합니다. 이 함수는 현재 완전히 구현되어 있습니다. */
enum vm_type page_get_type(struct page *page)
{
    int ty = VM_TYPE(page->operations->type);
    switch (ty)
    {
        case VM_UNINIT:
            return VM_TYPE(page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
/* 헬퍼 함수들 */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* 초기화 함수를 사용하여 보류 중인(pending) 페이지 객체를 생성합니다. 페이지를
 * 생성하려면 직접 생성하지 말고 이 함수 또는 `vm_alloc_page`를 통해 생성해야
 * 합니다. */
// 새로운 페이지 요청이 커널에 들어오면, 먼저 vm_alloc_page_with_initializer
// 함수가 호출됨 새로운 페이지 구조체를 할당하고, 페이지 타입에 따라 적절한
// 초기화 함수를 설정
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux)
{
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    /* upage가 이미 점유되었는지 여부를 확인합니다. */
    if (spt_find_page(spt, upage) == NULL)
    {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        /* TODO: 페이지를 생성하고, VM 타입에 따라 초기화 함수를 가져온 다음,
         * TODO: uninit_new를 호출하여 "uninit" 페이지 구조체를 생성하세요.
         * TODO: uninit_new를 호출한 후 필드를 수정해야 합니다. */

        // 페이지 생성 (새로운 페이지 구조체 할당)
        struct page *page = (struct page *) malloc(sizeof(struct page));
        if (page == NULL) return false;

        // VM 타입에 따른 초기화 함수 설정
        bool (*page_initilazer)(struct page *, enum vm_type type, void *aux) =
            NULL;

        switch (VM_TYPE(type))
        {
            case VM_ANON:  // 익명 페이지의 경우
                page_initilazer = anon_initializer;
                break;
            case VM_FILE:  // 파일 기반 페이지의 경우
                page_initilazer = file_backed_initializer;
                break;
            default:
                free(page);
                return false;
        }

        

        // uninit_new를 호출하여 "uninit" 페이지 구조체를 생성
        uninit_new(page, upage, init, type, aux, page_initilazer);

        page->writable = writable;
        /* TODO: Insert the page into the spt. */
        /* TODO: 페이지를 spt에 삽입하세요. */
        if (!spt_insert_page(spt, page))
        {
            free(page);
            return false;
        }
			return true;
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
/* spt에서 VA를 찾아 페이지를 반환합니다. 오류 발생 시 NULL을 반환합니다. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED,
                           void *va UNUSED)
{
    // struct page *page = NULL;
    /* TODO: Fill this function. */
    /* TODO: 이 함수를 완성하세요. */

    struct page temp;
    temp.va = pg_round_down(va);  // 페이지 단위로 정렬

    struct hash_elem *e = hash_find(&spt->spt_hash, &temp.hash_elem);
    if (e == NULL)
    {
        return NULL;
    }

    return hash_entry(e, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
/* 유효성 검사를 통해 PAGE를 spt에 삽입합니다. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
                     struct page *page UNUSED)
{
    int succ = false;
    /* TODO: Fill this function. */
    /* TODO: 이 함수를 완성하세요. */

    // hash_insert()는 이미 동일한 key가 있는 경우 기존의 hash_elem 포인터를
    // 반환
    if (hash_insert(&spt->spt_hash, &page->hash_elem) == NULL)
    {
        succ = true;
    }

    return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
/* 교체될 struct frame을 가져옵니다. */
static struct frame *vm_get_victim(void)
{
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */
    /* TODO: 교체 정책은 여러분에게 달려 있습니다. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
/* 한 페이지를 교체하고 해당하는 프레임을 반환합니다.
 * 오류 발생 시 NULL을 반환합니다. */
static struct frame *vm_evict_frame(void)
{
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */
    /* TODO: 희생자 페이지를 스왑 아웃하고 교체된 프레임을 반환하세요. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/* palloc()을 호출하여 프레임을 가져옵니다. 사용 가능한 페이지가 없으면
 * 페이지를 교체하여 반환합니다. 이 함수는 항상 유효한 주소를 반환합니다.
 * 즉, 사용자 풀 메모리가 가득 차면, 이 함수는 사용 가능한 메모리 공간을
 * 얻기 위해 프레임을 교체합니다. */
static struct frame *vm_get_frame(void)
{
    struct frame *frame = NULL;
    /* TODO: Fill this function. */
    /* TODO: 이 함수를 완성하세요. */

    // 사용자 풀에서 새 물리 페이지를 가져옴
    void *kva = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kva == NULL)
    {
        PANIC("todo");
    }

    // 프레임 할당
    frame = malloc(sizeof(struct frame));
    if (frame == NULL) PANIC("todo");

    // 멤버 초기화
    frame->kva = kva;
    frame->page = NULL;

    lock_acquire(&frame_table_lock);
    list_push_back(&frame_table, &frame->elem);
    lock_release(&frame_table_lock);

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
/* 스택을 확장합니다. */
static void vm_stack_growth(void *addr UNUSED)
{
    void *page_start = pg_round_down(addr);

    // 페이지 구조 할당
    // SPT에 스택 페이지(anonymous) 등록
    if (!vm_alloc_page_with_initializer(VM_ANON | VM_MARKER_0, page_start, true,
                                        NULL, NULL))
        return;

    // va에 대해 페이지를 할당 (물리 메모리 확보)
    vm_claim_page(page_start);
}

/* Handle the fault on write_protected page */
/* 쓰기 보호(write-protected) 페이지에서의 폴트(fault)를 처리합니다. */
static bool vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
/* 성공 시 true를 반환합니다. */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED,
                         bool not_present UNUSED)
{
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    /* TODO: Validate the fault */
    /* TODO: 폴트의 유효성을 검사하세요. */
    /* TODO: Your code goes here */
    /* TODO: 여기에 코드를 작성하세요. */

// 이미 물리 메모리에 매핑되어 있는데도 폴트가 발생한 경우
    if (!not_present) return false;

		if (is_kernel_vaddr(addr)) return false;

    // SPT에서 addr에 해당하는 struct page를 찾음
    page = spt_find_page(spt, addr);

// page == NULL : 아직 메모리에 로드되지 않았거나 스택처럼 새로 할당되어야
    // 하는 영역임
    // 스택 확장을 식별
    // addr >= f->rsp - 8 : 페이지 폴트가 발생한
    // 주소가 스택 포인터와 충분히 가까워 스택 확장 요청으로 간주될 수 있는지를
    // 판단하는 임계값
    if (page == NULL)
    {
        if (not_present && is_user_vaddr(addr) &&
            addr >= thread_current()->user_rsp - 8 && addr <= USER_STACK)
        {
            vm_stack_growth(addr);
            return true;
        }
        return false;
    }

    return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
/* 페이지를 해제합니다.
 * 이 함수를 수정하지 마십시오. */
void vm_dealloc_page(struct page *page)
{
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
/* VA에 할당된 페이지를 클레임(claim)합니다. */
bool vm_claim_page(void *va UNUSED)
{
    struct thread *curr = thread_current();
    /* TODO: Fill this function */
    /* TODO: 이 함수를 완성하세요. */
    // 주어진 가상 주소 va에 대해서 페이지 할당
    // SPT를 확인하고 va에 해당하는 page를 가져오기
    struct page *page = spt_find_page(&curr->spt, va);
    if (page == NULL) return false;

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
/* PAGE를 클레임하고 mmu를 설정합니다. */
static bool vm_do_claim_page(struct page *page)
{
    struct frame *frame = vm_get_frame();

    /* Set links */
    /* 링크를 설정합니다. */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    /* TODO: 페이지의 가상 주소(VA)를 프레임의 물리 주소(PA)에 매핑하는
     * TODO: 페이지 테이블 엔트리를 삽입하세요. */
    struct thread *curr = thread_current();
    bool success =
        pml4_set_page(curr->pml4, page->va, frame->kva, page->writable);
    if (!success) return false;

    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
/* 새로운 보조 페이지 테이블을 초기화합니다. */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
    hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
/* 보조 페이지 테이블을 src에서 dst로 복사합니다. */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED)
{
}

/* Free the resource hold by the supplemental page table */
/* 보조 페이지 테이블이 소유한 자원을 해제합니다. */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    /* TODO: 스레드가 소유한 모든 보조 페이지 테이블을 파괴하고
     * TODO: 수정된 모든 내용을 저장소에 다시 기록하세요. */
}