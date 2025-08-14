#include "threads/malloc.h"

#include <debug.h>
#include <list.h>
#include <round.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* malloc()의 간단한 구현.

   각 요청의 크기(바이트)는 2의 거듭제곱으로 반올림되고
   해당 크기의 블록을 관리하는 "descriptor"에 할당됩니다.
   descriptor는 자유 블록들의 목록을 유지합니다. 자유 목록이
   비어있지 않으면 그 블록 중 하나를 사용하여 요청을 만족시킵니다.

   그렇지 않으면 "arena"라고 불리는 새로운 메모리 페이지를
   페이지 할당자로부터 획득합니다(사용 가능한 것이 없으면
   malloc()은 null 포인터를 반환합니다). 새로운 arena는
   블록들로 나뉘고, 모든 블록들이 descriptor의 자유 목록에 추가됩니다.
   그런 다음 새로운 블록 중 하나를 반환합니다.

   블록을 해제할 때는 그것을 해당 descriptor의 자유 목록에 추가합니다.
   하지만 블록이 있던 arena에 사용 중인 블록이 더 이상 없으면,
   arena의 모든 블록들을 자유 목록에서 제거하고 arena를 페이지 할당자에게
   다시 돌려줍니다.

   이 방식으로는 2kB보다 큰 블록을 처리할 수 없습니다.
   descriptor와 함께 단일 페이지에 맞추기에는 너무 크기 때문입니다.
   이러한 블록들은 페이지 할당자로 연속된 페이지를 할당하고
   할당된 블록의 arena 헤더 시작 부분에 할당 크기를 저장하여 처리합니다. */

/* Descriptor. */
struct desc
{
    size_t block_size;       /* 각 요소의 크기(바이트). */
    size_t blocks_per_arena; /* arena당 블록 수. */
    struct list free_list;   /* 자유 블록들의 목록. */
    struct lock lock;        /* 락. */
};

/* arena 손상 감지를 위한 매직 넘버. */
#define ARENA_MAGIC 0x9a548eed

/* Arena. */
struct arena
{
    unsigned magic;    /* 항상 ARENA_MAGIC으로 설정. */
    struct desc *desc; /* 소유하는 descriptor, 큰 블록의 경우 null. */
    size_t free_cnt; /* 자유 블록 수; 큰 블록의 경우 페이지 수. */
};

/* Free block. */
struct block
{
    struct list_elem free_elem; /* Free list element. */
};

/* Our set of descriptors. */
static struct desc descs[10]; /* Descriptors. */
static size_t desc_cnt;       /* Number of descriptors. */

static struct arena *block_to_arena(struct block *);
static struct block *arena_to_block(struct arena *, size_t idx);

/* malloc() descriptor들을 초기화합니다. */
void malloc_init(void)
{
    size_t block_size;

    for (block_size = 16; block_size < PGSIZE / 2; block_size *= 2)
    {
        struct desc *d = &descs[desc_cnt++];
        ASSERT(desc_cnt <= sizeof descs / sizeof *descs);
        d->block_size = block_size;
        d->blocks_per_arena = (PGSIZE - sizeof(struct arena)) / block_size;
        list_init(&d->free_list);
        lock_init(&d->lock);
    }
}

/* 최소 SIZE 바이트의 새로운 블록을 획득하고 반환합니다.
   메모리를 사용할 수 없으면 null 포인터를 반환합니다. */
void *malloc(size_t size)
{
    struct desc *d;
    struct block *b;
    struct arena *a;

    /* null 포인터는 0 바이트 요청을 만족시킵니다. */
    if (size == 0) return NULL;

    /* SIZE 바이트 요청을 만족시키는 가장 작은 descriptor를 찾습니다. */
    for (d = descs; d < descs + desc_cnt; d++)
        if (d->block_size >= size) break;
    if (d == descs + desc_cnt)
    {
        /* SIZE가 어떤 descriptor에도 너무 큽니다.
           SIZE와 arena를 담을 수 있는 충분한 페이지를 할당합니다. */
        size_t page_cnt = DIV_ROUND_UP(size + sizeof *a, PGSIZE);
        a = palloc_get_multiple(0, page_cnt);
        if (a == NULL) return NULL;

        /* PAGE_CNT 페이지의 큰 블록을 나타내도록 arena를 초기화하고 반환합니다.
         */
        a->magic = ARENA_MAGIC;
        a->desc = NULL;
        a->free_cnt = page_cnt;
        return a + 1;
    }

    lock_acquire(&d->lock);

    /* 자유 목록이 비어있으면 새로운 arena를 생성합니다. */
    if (list_empty(&d->free_list))
    {
        size_t i;

        /* 페이지를 할당합니다. */
        a = palloc_get_page(0);
        if (a == NULL)
        {
            lock_release(&d->lock);
            return NULL;
        }

        /* arena를 초기화하고 그 블록들을 자유 목록에 추가합니다. */
        a->magic = ARENA_MAGIC;
        a->desc = d;
        a->free_cnt = d->blocks_per_arena;
        for (i = 0; i < d->blocks_per_arena; i++)
        {
            struct block *b = arena_to_block(a, i);
            list_push_back(&d->free_list, &b->free_elem);
        }
    }

    /* 자유 목록에서 블록을 가져와서 반환합니다. */
    b = list_entry(list_pop_front(&d->free_list), struct block, free_elem);
    a = block_to_arena(b);
    a->free_cnt--;
    lock_release(&d->lock);
    return b;
}

/* A곱하기 B 바이트를 0으로 초기화하여 할당하고 반환합니다.
   메모리를 사용할 수 없으면 null 포인터를 반환합니다. */
void *calloc(size_t a, size_t b)
{
    void *p;
    size_t size;

    /* 블록 크기를 계산하고 size_t에 맞는지 확인합니다. */
    size = a * b;
    if (size < a || size < b) return NULL;

    /* 메모리를 할당하고 0으로 초기화합니다. */
    p = malloc(size);
    if (p != NULL) memset(p, 0, size);

    return p;
}

/* BLOCK에 할당된 바이트 수를 반환합니다. */
static size_t block_size(void *block)
{
    struct block *b = block;
    struct arena *a = block_to_arena(b);
    struct desc *d = a->desc;

    return d != NULL ? d->block_size : PGSIZE * a->free_cnt - pg_ofs(block);
}

/* OLD_BLOCK을 NEW_SIZE 바이트로 크기를 조정하려고 시도합니다.
   이 과정에서 이동할 수 있습니다.
   성공하면 새로운 블록을 반환하고, 실패하면 null 포인터를 반환합니다.
   null OLD_BLOCK으로 호출하는 것은 malloc(NEW_SIZE)와 동일합니다.
   0 NEW_SIZE로 호출하는 것은 free(OLD_BLOCK)와 동일합니다. */
void *realloc(void *old_block, size_t new_size)
{
    if (new_size == 0)
    {
        free(old_block);
        return NULL;
    }
    else
    {
        void *new_block = malloc(new_size);
        if (old_block != NULL && new_block != NULL)
        {
            size_t old_size = block_size(old_block);
            size_t min_size = new_size < old_size ? new_size : old_size;
            memcpy(new_block, old_block, min_size);
            free(old_block);
        }
        return new_block;
    }
}

/* 이전에 malloc(), calloc(), 또는 realloc()으로 할당된 블록 P를 해제합니다. */
void free(void *p)
{
    if (p != NULL)
    {
        struct block *b = p;
        struct arena *a = block_to_arena(b);
        struct desc *d = a->desc;

        if (d != NULL)
        {
            /* 일반 블록입니다. 여기서 처리합니다. */

#ifndef NDEBUG
            /* use-after-free 버그를 감지하는 데 도움이 되도록 블록을 지웁니다.
             */
            memset(b, 0xcc, d->block_size);
#endif

            lock_acquire(&d->lock);

            /* 블록을 자유 목록에 추가합니다. */
            list_push_front(&d->free_list, &b->free_elem);

            /* arena가 이제 완전히 사용되지 않으면 해제합니다. */
            if (++a->free_cnt >= d->blocks_per_arena)
            {
                size_t i;

                ASSERT(a->free_cnt == d->blocks_per_arena);
                for (i = 0; i < d->blocks_per_arena; i++)
                {
                    struct block *b = arena_to_block(a, i);
                    list_remove(&b->free_elem);
                }
                palloc_free_page(a);
            }

            lock_release(&d->lock);
        }
        else
        {
            /* 큰 블록입니다. 그 페이지들을 해제합니다. */
            palloc_free_multiple(a, a->free_cnt);
            return;
        }
    }
}

/* 블록 B가 속한 arena를 반환합니다. */
static struct arena *block_to_arena(struct block *b)
{
    struct arena *a = pg_round_down(b);

    /* arena가 유효한지 확인합니다. */
    ASSERT(a != NULL);
    ASSERT(a->magic == ARENA_MAGIC);

    /* 블록이 arena에 대해 적절히 정렬되었는지 확인합니다. */
    ASSERT(a->desc == NULL ||
           (pg_ofs(b) - sizeof *a) % a->desc->block_size == 0);
    ASSERT(a->desc != NULL || pg_ofs(b) == sizeof *a);

    return a;
}

/* arena A 내에서 (IDX - 1)번째 블록을 반환합니다. */
static struct block *arena_to_block(struct arena *a, size_t idx)
{
    ASSERT(a != NULL);
    ASSERT(a->magic == ARENA_MAGIC);
    ASSERT(idx < a->desc->blocks_per_arena);
    return (struct block *) ((uint8_t *) a + sizeof *a +
                             idx * a->desc->block_size);
}
