/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "lib/kernel/bitmap.h" // 비트맵 사용을 위한 헤더 추가
#include "threads/mmu.h" // 일단 PGSIZE 때문에 추가 - 사실 vaddr.h에 있긴한데 혹시 mmu.h에 있는거도 필요할까봐

struct bitmap *swap_table; // 스왑테이블 주소 전역변수

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk; // 스왑디스크 주소 전역변수
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1); // 스왑디스크 불러오는 함수 - (1,1)이 스왑디스크를 의미
	swap_table = bitmap_create(disk_size(swap_disk) / PGSIZE); // 비트맵 생성 - 디스크 사이즈/페이지 사이즈 = 총 스왑 테이블 엔트리 개수만큼

}	

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->swap_table_idx = 0; // 일단 0으로 초기화
	anon_page->is_swaped_out = false;

}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	ASSERT(anon_page->is_swaped_out); // swaped out된 상태일 것

	size_t idx = anon_page->swap_table_idx;

	if (!bitmap_test(swap_table, idx))
		return false; // 뭔가 잘못됨..

	for (int i = 0; i < 8; i++) {
		disk_read(swap_disk, idx*8 + i, kva + DISK_SECTOR_SIZE*i);
	}

	bitmap_reset(swap_table, idx);
	anon_page->is_swaped_out = false;
	return true;

}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	ASSERT(!anon_page->is_swaped_out); // 아직 swaped out되지 않은 상태일 것
	
	if (bitmap_all(swap_table, 0, bitmap_size(swap_table))) // 만약 스왑 테이블이 전부 true이면
		PANIC("PANIC : SWAP_TABLE_IS_FULL"); // 스왑 디스크가 꽉 찬 것이므로 커널 패닉

	for (int idx = 0; idx < bitmap_size(swap_table); idx++) {
		if (!bitmap_test(swap_table, idx)) {
			for (int i = 0; i < 8; i++) {
				disk_write(swap_disk, idx*8 + i, page->va + DISK_SECTOR_SIZE*i); // 이 부분 GPT 도움받음 -> 반드시 나중에 이유 정리할것
			}
			bitmap_mark(swap_table, idx);
			anon_page->swap_table_idx = idx;
			anon_page->is_swaped_out = true;
			return true;
		}
	}

}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
