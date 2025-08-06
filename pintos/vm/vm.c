/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h" // 해시테이블 사용을 위한 헤더 추가
#include "threads/mmu.h" // 페이지테이블 조작을 위한 헤더 추가
#include "devices/disk.h" // 스왑디스크 등록을 위한 헤더 추가

struct disk *swap_disk; // 스왑디스크 주소 전역변수


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */

}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initializer according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *vm_entry = malloc(sizeof(struct page));
		if (type == VM_ANON)
			uninit_new(vm_entry, upage, init, type, aux, anon_initializer);
		else if (type == VM_FILE)
			uninit_new(vm_entry, upage, init, type, aux, file_backed_initializer);

		vm_entry->frame = vm_get_frame();
		vm_entry->writable = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, &vm_entry);

	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *p;
	/* TODO: Fill this function. */
	struct hash_elem *e;

	p->va = va;
	e = hash_find(&spt->spt_list, &p->spt_elem);

	return e != NULL ? hash_entry(e, struct page, spt_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if (spt_find_page(spt, page->va))
		return succ; // 이미 존재하면 false 반환 -> 아닐수도 있음

	else if (hash_insert(&spt->spt_list, &page->spt_elem) == NULL)
		succ = true;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	frame = calloc(1, sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	
	if (frame->kva == NULL) // 아직 스왑 구현 전 - 스왑 하면서 여기 바껴야함
		PANIC("todo");

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	if (!not_present) //읽기 전용에 쓰려고 했으면 진짜폴트 아님?
		return false;
	
	if (is_kernel_vaddr(addr)) // 페이지폴트가 커널영역 참조하려해서 발생했으면 진짜폴트
		return false;
	
	if ((page = spt_find_page(spt, &addr)) == NULL) // spt에 없으면
		return false; // 공유자원 있기 전까지는 일단 false (이부분은 추후 수정되어야함)
	

	return vm_do_claim_page (page); // spt에 있으면, 일단 프레임 요청해보러 간다
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
/* 이 함수는 언제쓰는건지 아직 감 못잡음 */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	/* TODO: Fill this function */

	if ((page = spt_find_page(spt, va)) == NULL) // spt에 없으면
		return false; // 공유자원 있기 전까지는 일단 false (이부분은 추후 수정되어야함)


	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct thread *t = thread_current(); // 근데 지금 이상황이 사용자쓰레드가 하는게 맞나..?
	struct frame *frame = vm_get_frame (); // 야 일단 프레임 내놔!!

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	pml4_set_page(t->pml4, page->va, frame->kva, page->writable); // 왠지 writable 정보가 page 구조체에 들어가야할듯..?


	return swap_in (page, frame->kva); // 여기서 page가 UNINIT이면 uninit_initialize로 간다!
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_list, page_hash, page_less, NULL);
	


}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}

/* 해시 테이블 구현용 함수 */

/* 페이지 p에 대한 해시 값을 반환합니다. */
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry(p_, struct page, spt_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

/* 페이지 a가 페이지 b보다 앞서면 true를 반환합니다. */
bool page_less(const struct hash_elem * a, const struct hash_elem * b, void * aux UNUSED) { 
    const struct page *a_ = hash_entry(a, struct page, spt_elem);
    const struct page *b_ = hash_entry(b, struct page, spt_elem);

    return a_->va > b_->va;
}