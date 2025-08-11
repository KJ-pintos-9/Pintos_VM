/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/mmu.h" // PGSIZE 때문에 추가
#include "userprog/syscall.h" // do_mmap, do_munmap 때문에 추가

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	file_page->is_swaped_out = false;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva)
{
    struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page)
{
    struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page)
{
    struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap - 얘가 마치 lazy_load_segment와 같은 역할을 해야 할 듯 */
// void *
// do_mmap (void *addr, size_t length, int writable,
// 		struct file *file, off_t offset) {
// 	if ((uint64_t)addr % PGSIZE != 0 || addr == 0 || length == 0) // addr가 페이지 정렬되어있어야 한다는 조건 구현 - 아닐수도 있음
// 		return NULL;

	/* 일단 페이지 몇개가 필요한지 계산 */
	/* length /  */
	
	// if (vm_alloc_page_with_initializer(VM_FILE, addr, writable, )) //?
	// 	return addr;
	

// }

bool
do_mmap (struct page *page, void *aux)
{
	struct mmap_page_info *info = (struct mmap_page_info *) aux;

	uint8_t *kva = page->frame->kva;

	if (info->file != NULL)
	{
		file_seek(info->file, info->offset);

		if (file_read(info->file, kva, info->bytes_read) != (int) info->bytes_read)
		{
			palloc_free_page(kva);
			return false;
		}


		memset(kva + info->bytes_read, 0, info->zero_bytes);
		return true;

	}

	return false;
}


/* Do the munmap */
void do_munmap(void *addr)
{
}
