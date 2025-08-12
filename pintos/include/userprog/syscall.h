#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

struct mmap_page_info 
{
	struct file *file;
	off_t offset;
	uint32_t bytes_read;
	uint32_t zero_bytes;
	bool is_mmap_called;
	int mmaped_pages_count;
};

#endif /* userprog/syscall.h */
