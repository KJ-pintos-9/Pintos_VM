#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct file_page
{
	bool is_swaped_out;
};

struct page;
enum vm_type;



void vm_file_init(void);
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva);
// void *do_mmap(void *addr, size_t length, int writable, struct file *file,
//               off_t offset);
bool do_mmap (struct page *page, void *aux);
void do_munmap(void *va);
#endif
