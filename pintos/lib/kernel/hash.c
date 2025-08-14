/* Hash table.

   This data structure is thoroughly documented in the Tour of
   Pintos for Project 3.

   See hash.h for basic information. */
/* 해시 테이블.

   이 자료구조는 프로젝트 3의 Pintos Tour에 자세히 설명되어 있습니다.

   기본 정보는 hash.h를 참조하세요. */

#include "hash.h"

#include "../debug.h"
#include "threads/malloc.h"
#include "vm/vm.h"

#define list_elem_to_hash_elem(LIST_ELEM) \
    list_entry(LIST_ELEM, struct hash_elem, list_elem)

static struct list *find_bucket(struct hash *, struct hash_elem *);
static struct hash_elem *find_elem(struct hash *, struct list *,
                                   struct hash_elem *);
static void insert_elem(struct hash *, struct list *, struct hash_elem *);
static void remove_elem(struct hash *, struct hash_elem *);
static void rehash(struct hash *);

/* Initializes hash table H to compute hash values using HASH and
   compare hash elements using LESS, given auxiliary data AUX. */
/* 보조 데이터 AUX가 주어졌을 때, HASH를 사용하여 해시 값을 계산하고
   LESS를 사용하여 해시 요소를 비교하도록 해시 테이블 H를 초기화합니다. */
bool hash_init(struct hash *h, hash_hash_func *hash, hash_less_func *less,
               void *aux)
{
    h->elem_cnt = 0;
    h->bucket_cnt = 4;
    h->buckets = malloc(sizeof *h->buckets * h->bucket_cnt);
    h->hash = hash;
    h->less = less;
    h->aux = aux;

    if (h->buckets != NULL)
    {
        hash_clear(h, NULL);
        return true;
    }
    else
        return false;
}

/* 페이지 p에 대한 해시 값을 반환합니다. */
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

/* 페이지 a가 페이지 b보다 앞서면 true를 반환합니다. */
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED)
{
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);
    return a->va < b->va;
}

/* Removes all the elements from H.

   If DESTRUCTOR is non-null, then it is called for each element
   in the hash.  DESTRUCTOR may, if appropriate, deallocate the
   memory used by the hash element.  However, modifying hash
   table H while hash_clear() is running, using any of the
   functions hash_clear(), hash_destroy(), hash_insert(),
   hash_replace(), or hash_delete(), yields undefined behavior,
   whether done in DESTRUCTOR or elsewhere. */
/* H에서 모든 요소를 제거합니다.

   만약 DESTRUCTOR가 널이 아니면, 해시의 각 요소에 대해 호출됩니다.
   DESTRUCTOR는 적절하다면 해시 요소가 사용한 메모리를 해제할 수 있습니다.
   그러나 DESTRUCTOR 내부에서든 다른 곳에서든, hash_clear()가 실행되는 동안
   hash_clear(), hash_destroy(), hash_insert(), hash_replace(), 또는
   hash_delete()와 같은 함수를 사용하여 해시 테이블 H를 수정하는 것은
   정의되지 않은 동작을 유발합니다. */
void hash_clear(struct hash *h, hash_action_func *destructor)
{
    size_t i;

    for (i = 0; i < h->bucket_cnt; i++)
    {
        struct list *bucket = &h->buckets[i];

        if (destructor != NULL)
            while (!list_empty(bucket))
            {
                struct list_elem *list_elem = list_pop_front(bucket);
                struct hash_elem *hash_elem = list_elem_to_hash_elem(list_elem);
                destructor(hash_elem, h->aux);
            }

        list_init(bucket);
    }

    h->elem_cnt = 0;
}

/* Destroys hash table H.

   If DESTRUCTOR is non-null, then it is first called for each
   element in the hash.  DESTRUCTOR may, if appropriate,
   deallocate the memory used by the hash element.  However,
   modifying hash table H while hash_clear() is running, using
   any of the functions hash_clear(), hash_destroy(),
   hash_insert(), hash_replace(), or hash_delete(), yields
   undefined behavior, whether done in DESTRUCTOR or
   elsewhere. */
/* 해시 테이블 H를 파괴합니다.

   만약 DESTRUCTOR가 널이 아니면, 해시의 각 요소에 대해 먼저 호출됩니다.
   DESTRUCTOR는 적절하다면 해시 요소가 사용한 메모리를 해제할 수 있습니다.
   그러나 DESTRUCTOR 내부에서든 다른 곳에서든, hash_destroy()가 실행되는 동안
   hash_clear(), hash_destroy(), hash_insert(), hash_replace(), 또는
   hash_delete()와 같은 함수를 사용하여 해시 테이블 H를 수정하는 것은
   정의되지 않은 동작을 유발합니다. */
void hash_destroy(struct hash *h, hash_action_func *destructor)
{
    if (destructor != NULL) hash_clear(h, destructor);
    free(h->buckets);
}

/* Inserts NEW into hash table H and returns a null pointer, if
   no equal element is already in the table.
   If an equal element is already in the table, returns it
   without inserting NEW. */
/* 해시 테이블 H에 NEW를 삽입하고, 만약 동일한 요소가 이미 테이블에 없다면
   널 포인터를 반환합니다. 만약 동일한 요소가 이미 테이블에 있다면,
   NEW를 삽입하지 않고 기존 요소를 반환합니다. */
struct hash_elem *hash_insert(struct hash *h, struct hash_elem *new)
{
    struct list *bucket = find_bucket(h, new);
    struct hash_elem *old = find_elem(h, bucket, new);

    if (old == NULL) insert_elem(h, bucket, new);

    rehash(h);

    return old;
}

/* Inserts NEW into hash table H, replacing any equal element
   already in the table, which is returned. */
/* 해시 테이블 H에 NEW를 삽입하고, 이미 테이블에 있는 동일한 요소를
   교체하며, 교체된 요소를 반환합니다. */
struct hash_elem *hash_replace(struct hash *h, struct hash_elem *new)
{
    struct list *bucket = find_bucket(h, new);
    struct hash_elem *old = find_elem(h, bucket, new);

    if (old != NULL) remove_elem(h, old);
    insert_elem(h, bucket, new);

    rehash(h);

    return old;
}

/* Finds and returns an element equal to E in hash table H, or a
   null pointer if no equal element exists in the table. */
/* 해시 테이블 H에서 E와 동일한 요소를 찾아 반환합니다. 테이블에
   동일한 요소가 존재하지 않으면 널 포인터를 반환합니다. */
struct hash_elem *hash_find(struct hash *h, struct hash_elem *e)
{
    return find_elem(h, find_bucket(h, e), e);
}

/* Finds, removes, and returns an element equal to E in hash
   table H.  Returns a null pointer if no equal element existed
   in the table.

   If the elements of the hash table are dynamically allocated,
   or own resources that are, then it is the caller's
   responsibility to deallocate them. */
/* 해시 테이블 H에서 E와 동일한 요소를 찾아 제거하고 반환합니다.
   테이블에 동일한 요소가 존재하지 않으면 널 포인터를 반환합니다.

   만약 해시 테이블의 요소가 동적으로 할당되었거나, 그러한 자원을
   소유하고 있다면, 그들을 해제하는 것은 호출자의 책임입니다. */
struct hash_elem *hash_delete(struct hash *h, struct hash_elem *e)
{
    struct hash_elem *found = find_elem(h, find_bucket(h, e), e);
    if (found != NULL)
    {
        remove_elem(h, found);
        rehash(h);
    }
    return found;
}

/* Calls ACTION for each element in hash table H in arbitrary
   order.
   Modifying hash table H while hash_apply() is running, using
   any of the functions hash_clear(), hash_destroy(),
   hash_insert(), hash_replace(), or hash_delete(), yields
   undefined behavior, whether done from ACTION or elsewhere. */
/* 해시 테이블 H의 각 요소에 대해 임의의 순서로 ACTION을 호출합니다.
   ACTION 내부에서든 다른 곳에서든, hash_apply()가 실행되는 동안
   hash_clear(), hash_destroy(), hash_insert(), hash_replace(),
   또는 hash_delete()와 같은 함수를 사용하여 해시 테이블 H를
   수정하는 것은 정의되지 않은 동작을 유발합니다. */
void hash_apply(struct hash *h, hash_action_func *action)
{
    size_t i;

    ASSERT(action != NULL);

    for (i = 0; i < h->bucket_cnt; i++)
    {
        struct list *bucket = &h->buckets[i];
        struct list_elem *elem, *next;

        for (elem = list_begin(bucket); elem != list_end(bucket); elem = next)
        {
            next = list_next(elem);
            action(list_elem_to_hash_elem(elem), h->aux);
        }
    }
}

/* Initializes I for iterating hash table H.

   Iteration idiom:

   struct hash_iterator i;

   hash_first (&i, h);
   while (hash_next (&i))
   {
   struct foo *f = hash_entry (hash_cur (&i), struct foo, elem);
   ...do something with f...
   }

   Modifying hash table H during iteration, using any of the
   functions hash_clear(), hash_destroy(), hash_insert(),
   hash_replace(), or hash_delete(), invalidates all
   iterators. */
/* 해시 테이블 H를 순회하기 위해 I를 초기화합니다.

   순회 관용구:

   struct hash_iterator i;

   hash_first (&i, h);
   while (hash_next (&i))
   {
   struct foo *f = hash_entry (hash_cur (&i), struct foo, elem);
   ... f로 무언가를 수행 ...
   }

   순회 중에 hash_clear(), hash_destroy(), hash_insert(),
   hash_replace(), 또는 hash_delete()와 같은 함수를 사용하여
   해시 테이블 H를 수정하는 것은 모든 순회자를 무효화합니다. */
void hash_first(struct hash_iterator *i, struct hash *h)
{
    ASSERT(i != NULL);
    ASSERT(h != NULL);

    i->hash = h;
    i->bucket = i->hash->buckets;
    i->elem = list_elem_to_hash_elem(list_head(i->bucket));
}

/* Advances I to the next element in the hash table and returns
   it.  Returns a null pointer if no elements are left.  Elements
   are returned in arbitrary order.

   Modifying a hash table H during iteration, using any of the
   functions hash_clear(), hash_destroy(), hash_insert(),
   hash_replace(), or hash_delete(), invalidates all
   iterators. */
/* I를 해시 테이블의 다음 요소로 이동시키고 반환합니다.
   남은 요소가 없으면 널 포인터를 반환합니다. 요소는 임의의 순서로 반환됩니다.

   순회 중에 hash_clear(), hash_destroy(), hash_insert(),
   hash_replace(), 또는 hash_delete()와 같은 함수를 사용하여
   해시 테이블 H를 수정하는 것은 모든 순회자를 무효화합니다. */
struct hash_elem *hash_next(struct hash_iterator *i)
{
    ASSERT(i != NULL);

    i->elem = list_elem_to_hash_elem(list_next(&i->elem->list_elem));
    while (i->elem == list_elem_to_hash_elem(list_end(i->bucket)))
    {
        if (++i->bucket >= i->hash->buckets + i->hash->bucket_cnt)
        {
            i->elem = NULL;
            break;
        }
        i->elem = list_elem_to_hash_elem(list_begin(i->bucket));
    }

    return i->elem;
}

/* Returns the current element in the hash table iteration, or a
   null pointer at the end of the table.  Undefined behavior
   after calling hash_first() but before hash_next(). */
/* 해시 테이블 순회 중 현재 요소를 반환하거나, 테이블 끝에서는
   널 포인터를 반환합니다. hash_first() 호출 후 hash_next() 호출
   전에는 정의되지 않은 동작입니다. */
struct hash_elem *hash_cur(struct hash_iterator *i)
{
    return i->elem;
}

/* Returns the number of elements in H. */
/* H에 있는 요소의 개수를 반환합니다. */
size_t hash_size(struct hash *h)
{
    return h->elem_cnt;
}

/* Returns true if H contains no elements, false otherwise. */
/* H에 요소가 없으면 true를, 그렇지 않으면 false를 반환합니다. */
bool hash_empty(struct hash *h)
{
    return h->elem_cnt == 0;
}

/* Fowler-Noll-Vo hash constants, for 32-bit word sizes. */
/* 32비트 워드 크기를 위한 Fowler-Noll-Vo 해시 상수. */
#define FNV_64_PRIME 0x00000100000001B3UL
#define FNV_64_BASIS 0xcbf29ce484222325UL

/* Returns a hash of the SIZE bytes in BUF. */
/* BUF에 있는 SIZE 바이트의 해시를 반환합니다. */
uint64_t hash_bytes(const void *buf_, size_t size)
{
    /* Fowler-Noll-Vo 32-bit hash, for bytes. */
    /* 바이트를 위한 Fowler-Noll-Vo 32비트 해시. */
    const unsigned char *buf = buf_;
    uint64_t hash;

    ASSERT(buf != NULL);

    hash = FNV_64_BASIS;
    while (size-- > 0) hash = (hash * FNV_64_PRIME) ^ *buf++;

    return hash;
}

/* Returns a hash of string S. */
/* 문자열 S의 해시를 반환합니다. */
uint64_t hash_string(const char *s_)
{
    const unsigned char *s = (const unsigned char *) s_;
    uint64_t hash;

    ASSERT(s != NULL);

    hash = FNV_64_BASIS;
    while (*s != '\0') hash = (hash * FNV_64_PRIME) ^ *s++;

    return hash;
}

/* Returns a hash of integer I. */
/* 정수 I의 해시를 반환합니다. */
uint64_t hash_int(int i)
{
    return hash_bytes(&i, sizeof i);
}

/* Returns the bucket in H that E belongs in. */
/* E가 속하는 H의 버킷을 반환합니다. */
static struct list *find_bucket(struct hash *h, struct hash_elem *e)
{
    size_t bucket_idx = h->hash(e, h->aux) & (h->bucket_cnt - 1);
    return &h->buckets[bucket_idx];
}

/* Searches BUCKET in H for a hash element equal to E.  Returns
   it if found or a null pointer otherwise. */
/* H의 BUCKET에서 E와 동일한 해시 요소를 검색합니다. 찾으면 해당 요소를
   반환하고, 그렇지 않으면 널 포인터를 반환합니다. */
static struct hash_elem *find_elem(struct hash *h, struct list *bucket,
                                   struct hash_elem *e)
{
    struct list_elem *i;

    for (i = list_begin(bucket); i != list_end(bucket); i = list_next(i))
    {
        struct hash_elem *hi = list_elem_to_hash_elem(i);
        if (!h->less(hi, e, h->aux) && !h->less(e, hi, h->aux)) return hi;
    }
    return NULL;
}

/* Returns X with its lowest-order bit set to 1 turned off. */
/* X의 최하위 비트 1을 끈 값을 반환합니다. */
static inline size_t turn_off_least_1bit(size_t x)
{
    return x & (x - 1);
}

/* Returns true if X is a power of 2, otherwise false. */
/* X가 2의 거듭제곱이면 true를, 아니면 false를 반환합니다. */
static inline size_t is_power_of_2(size_t x)
{
    return x != 0 && turn_off_least_1bit(x) == 0;
}

/* Element per bucket ratios. */
/* 버킷당 요소 비율. */
#define MIN_ELEMS_PER_BUCKET 1  /* Elems/bucket < 1: reduce # of buckets. */
#define BEST_ELEMS_PER_BUCKET 2 /* Ideal elems/bucket. */
#define MAX_ELEMS_PER_BUCKET 4  /* Elems/bucket > 4: increase # of buckets. */

/* Changes the number of buckets in hash table H to match the
   ideal.  This function can fail because of an out-of-memory
   condition, but that'll just make hash accesses less efficient;
   we can still continue. */
/* 해시 테이블 H의 버킷 개수를 이상적인 수에 맞게 변경합니다.
   이 함수는 메모리 부족으로 인해 실패할 수 있지만, 이는 단지
   해시 접근을 덜 효율적으로 만들 뿐입니다. 우리는 계속 진행할 수 있습니다. */
static void rehash(struct hash *h)
{
    size_t old_bucket_cnt, new_bucket_cnt;
    struct list *new_buckets, *old_buckets;
    size_t i;

    ASSERT(h != NULL);

    /* Save old bucket info for later use. */
    /* 나중에 사용하기 위해 이전 버킷 정보를 저장합니다. */
    old_buckets = h->buckets;
    old_bucket_cnt = h->bucket_cnt;

    /* Calculate the number of buckets to use now.
       We want one bucket for about every BEST_ELEMS_PER_BUCKET.
       We must have at least four buckets, and the number of
       buckets must be a power of 2. */
    /* 이제 사용할 버킷의 개수를 계산합니다.
       BEST_ELEMS_PER_BUCKET 당 하나의 버킷을 원합니다.
       버킷은 최소 4개여야 하며, 버킷의 개수는 2의 거듭제곱이어야 합니다. */
    new_bucket_cnt = h->elem_cnt / BEST_ELEMS_PER_BUCKET;
    if (new_bucket_cnt < 4) new_bucket_cnt = 4;
    while (!is_power_of_2(new_bucket_cnt))
        new_bucket_cnt = turn_off_least_1bit(new_bucket_cnt);

    /* Don't do anything if the bucket count wouldn't change. */
    /* 버킷 개수가 변하지 않으면 아무것도 하지 않습니다. */
    if (new_bucket_cnt == old_bucket_cnt) return;

    /* Allocate new buckets and initialize them as empty. */
    /* 새로운 버킷을 할당하고 비어 있는 상태로 초기화합니다. */
    new_buckets = malloc(sizeof *new_buckets * new_bucket_cnt);
    if (new_buckets == NULL)
    {
        /* Allocation failed.  This means that use of the hash table will
           be less efficient.  However, it is still usable, so
           there's no reason for it to be an error. */
        /* 할당 실패. 이는 해시 테이블의 사용이 덜 효율적일 것임을 의미합니다.
           그러나 여전히 사용 가능하므로 오류로 간주할 필요는 없습니다. */
        return;
    }
    for (i = 0; i < new_bucket_cnt; i++) list_init(&new_buckets[i]);

    /* Install new bucket info. */
    /* 새로운 버킷 정보를 설치합니다. */
    h->buckets = new_buckets;
    h->bucket_cnt = new_bucket_cnt;

    /* Move each old element into the appropriate new bucket. */
    /* 각 이전 요소를 적절한 새로운 버킷으로 이동시킵니다. */
    for (i = 0; i < old_bucket_cnt; i++)
    {
        struct list *old_bucket;
        struct list_elem *elem, *next;

        old_bucket = &old_buckets[i];
        for (elem = list_begin(old_bucket); elem != list_end(old_bucket);
             elem = next)
        {
            struct list *new_bucket =
                find_bucket(h, list_elem_to_hash_elem(elem));
            next = list_next(elem);
            list_remove(elem);
            list_push_front(new_bucket, elem);
        }
    }

    free(old_buckets);
}

/* Inserts E into BUCKET (in hash table H). */
/* E를 BUCKET (해시 테이블 H 내)에 삽입합니다. */
static void insert_elem(struct hash *h, struct list *bucket,
                        struct hash_elem *e)
{
    h->elem_cnt++;
    list_push_front(bucket, &e->list_elem);
}

/* Removes E from hash table H. */
/* 해시 테이블 H에서 E를 제거합니다. */
static void remove_elem(struct hash *h, struct hash_elem *e)
{
    h->elem_cnt--;
    list_remove(&e->list_elem);
}