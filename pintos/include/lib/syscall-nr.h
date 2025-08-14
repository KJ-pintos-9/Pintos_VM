#ifndef __LIB_SYSCALL_NR_H
#define __LIB_SYSCALL_NR_H

/* 시스템 콜 번호들 */
enum
{
    /* 프로젝트 2 이후 */
    SYS_HALT,     /* 운영체제 중단 */
    SYS_EXIT,     /* 현재 프로세스 종료 */
    SYS_FORK,     /* 현재 프로세스 복제 */
    SYS_EXEC,     /* 현재 프로세스 전환 */
    SYS_WAIT,     /* 자식 프로세스 종료 대기 */
    SYS_CREATE,   /* 파일 생성 */
    SYS_REMOVE,   /* 파일 삭제 */
    SYS_OPEN,     /* 파일 열기 */
    SYS_FILESIZE, /* 파일 크기 얻기 */
    SYS_READ,     /* 파일에서 읽기 */
    SYS_WRITE,    /* 파일에 쓰기 */
    SYS_SEEK,     /* 파일 위치 변경 */
    SYS_TELL,     /* 파일 현재 위치 보고 */
    SYS_CLOSE,    /* 파일 닫기 */

    /* 프로젝트 3과 선택적으로 프로젝트 4 */
    SYS_MMAP,   /* 파일을 메모리에 매핑 */
    SYS_MUNMAP, /* 메모리 매핑 제거 */

    /* 프로젝트 4만 */
    SYS_CHDIR,   /* 현재 디렉토리 변경 */
    SYS_MKDIR,   /* 디렉토리 생성 */
    SYS_READDIR, /* 디렉토리 엔트리 읽기 */
    SYS_ISDIR,   /* fd가 디렉토리인지 테스트 */
    SYS_INUMBER, /* fd의 inode 번호 반환 */
    SYS_SYMLINK, /* 심볼릭 링크 생성 */

    /* 프로젝트 2 추가 기능 */
    SYS_DUP2, /* 파일 디스크립터 복제 */

    SYS_MOUNT,
    SYS_UMOUNT,
};

#endif /* lib/syscall-nr.h */
