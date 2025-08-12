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
		file_seek(page->file.file, page->file.offset);
		if (file_read(page->file.file, kva, page->file.bytes_read) == page->file.bytes_read)
			return false;

		return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page)
{
    struct file_page *file_page UNUSED = &page->file;
		file_seek(page->file.file, page->file.offset);
		if (file_write(page->file.file, page->frame->kva, page->file.bytes_read) != page->file.bytes_read)
			return false;
		
		return true;

}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page)
{
    struct file_page *file_page UNUSED = &page->file;
		struct thread *t = thread_current();

		if (pml4_is_dirty(t->pml4, page->va)) swap_out(page);
		file_close(page->file.file);
		

}

/* Do the mmap - 얘가 마치 lazy_load_segment와 같은 역할을 해야 할 듯 */

bool
do_mmap (struct page *page, void *aux)
{
	struct mmap_page_info *info = (struct mmap_page_info *) aux;

	page->is_mmap_called = info->is_mmap_called;
	page->mmaped_pages_count = info->mmaped_pages_count;

	if (page_get_type(page) == VM_FILE) {
		/* struct file_page에 정보 넣어주기 */
		page->file.file = info->file;
		page->file.offset = info->offset;
		page->file.bytes_read = info->bytes_read;
		page->file.zero_bytes = info->zero_bytes;
	}

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
	struct page *page;
	struct thread *t = thread_current();
	
	//if ((page = spt_find_page(&t->spt, addr)) == NULL) exit(-1);
	if (!(page = spt_find_page(&t->spt, addr))->is_mmap_called)
		exit(-1);

	int count = page->mmaped_pages_count;

	while (count) {
		if ((page = spt_find_page(&t->spt, pg_round_down(addr))) == NULL)
			exit(-1);
		
		spt_remove_page(&t->spt, page);

		pml4_clear_page(t->pml4, pg_round_down(addr));

		addr += PGSIZE;
		count--;
	}

}
