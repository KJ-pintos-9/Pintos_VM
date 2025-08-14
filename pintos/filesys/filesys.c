#include "filesys/filesys.h"

#include <debug.h>
#include <stdio.h>
#include <string.h>

#include "devices/disk.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"

/* 파일시스템을 포함하는 디스크 */
struct disk *filesys_disk;

static void do_format(void);

/* 파일시스템 모듈을 초기화
 * FORMAT이 true이면 파일시스템을 재포맷 */
void filesys_init(bool format)
{
    filesys_disk = disk_get(0, 1);
    if (filesys_disk == NULL)
        PANIC("hd0:1 (hdb) not present, file system initialization failed");

    inode_init();

#ifdef EFILESYS
    fat_init();

    if (format) do_format();

    fat_open();
#else
    /* Original FS */
    free_map_init();

    if (format) do_format();

    free_map_open();
#endif
}

/* 파일시스템 모듈을 종료하고, 쓰지 않은 데이터를
 * 디스크에 씀 */
void filesys_done(void)
{
    /* Original FS */
#ifdef EFILESYS
    fat_close();
#else
    free_map_close();
#endif
}

/* 주어진 INITIAL_SIZE로 NAME이라는 이름의 파일을 생성
 * 성공하면 true, 그렇지 않으면 false를 반환
 * NAME이라는 이름의 파일이 이미 존재하거나
 * 내부 메모리 할당이 실패하면 실패 */
bool filesys_create(const char *name, off_t initial_size)
{
    disk_sector_t inode_sector = 0;
    struct dir *dir = dir_open_root();
    bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                    inode_create(inode_sector, initial_size) &&
                    dir_add(dir, name, inode_sector));
    if (!success && inode_sector != 0) free_map_release(inode_sector, 1);
    dir_close(dir);

    return success;
}

/* 주어진 NAME을 가진 파일을 열기
 * 성공하면 새로운 파일을 반환하고, 그렇지 않으면
 * null 포인터를 반환
 * NAME이라는 이름의 파일이 존재하지 않거나
 * 내부 메모리 할당이 실패하면 실패 */
struct file *filesys_open(const char *name)
{
    struct dir *dir = dir_open_root();
    struct inode *inode = NULL;

    if (dir != NULL) dir_lookup(dir, name, &inode);
    dir_close(dir);

    return file_open(inode);
}

/* NAME이라는 이름의 파일을 삭제
 * 성공하면 true, 실패하면 false를 반환
 * NAME이라는 이름의 파일이 존재하지 않거나
 * 내부 메모리 할당이 실패하면 실패 */
bool filesys_remove(const char *name)
{
    struct dir *dir = dir_open_root();
    bool success = dir != NULL && dir_remove(dir, name);
    dir_close(dir);

    return success;
}

/* 파일시스템을 포맷 */
static void do_format(void)
{
    printf("Formatting file system...");

#ifdef EFILESYS
    /* FAT를 생성하고 디스크에 저장 */
    fat_create();
    fat_close();
#else
    free_map_create();
    if (!dir_create(ROOT_DIR_SECTOR, 16))
        PANIC("root directory creation failed");
    free_map_close();
#endif

    printf("done.\n");
}
