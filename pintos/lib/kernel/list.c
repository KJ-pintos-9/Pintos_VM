#include "list.h"

#include "../debug.h"

/* 우리의 이중 연결 리스트는 두 개의 헤더 요소를 가집니다: 첫 번째 요소 바로
   앞의 "head"와 마지막 요소 바로 뒤의 "tail"입니다. 앞쪽 헤더의 `prev' 링크는
   null이고, 뒤쪽 헤더의 `next' 링크도 null입니다. 다른 두 링크들은 리스트의
   내부 요소들을 통해 서로를 가리킵니다.

   빈 리스트는 다음과 같습니다:

   +------+     +------+
   <---| head |<--->| tail |--->
   +------+     +------+

   두 개의 요소를 가진 리스트는 다음과 같습니다:

   +------+     +-------+     +-------+     +------+
   <---| head |<--->|   1   |<--->|   2   |<--->| tail |<--->
   +------+     +-------+     +-------+     +------+

   이러한 대칭적 구조는 리스트 처리에서 많은 특수한 경우들을 제거합니다.
   예를 들어, list_remove()를 보면: 단지 두 개의 포인터 할당만 필요하고
   조건문이 없습니다. 이는 헤더 요소 없이 작성된 코드보다 훨씬 간단합니다.

   (각 헤더 요소의 포인터 중 하나만 사용되므로, 실제로는 이 간단함을
   희생하지 않고 단일 헤더 요소로 결합할 수 있습니다. 하지만 두 개의
   별도 요소를 사용하면 일부 연산에서 약간의 검사를 할 수 있어
   유용할 수 있습니다.) */

static bool is_sorted(struct list_elem *a, struct list_elem *b,
                      list_less_func *less, void *aux) UNUSED;

/* ELEM이 헤드인지 확인합니다. 헤드면 true, 아니면 false를 반환합니다. */
static inline bool is_head(struct list_elem *elem)
{
    return elem != NULL && elem->prev == NULL && elem->next != NULL;
}

/* ELEM이 내부 요소인지 확인합니다. 내부 요소면 true, 아니면 false를 반환합니다.
 */
static inline bool is_interior(struct list_elem *elem)
{
    return elem != NULL && elem->prev != NULL && elem->next != NULL;
}

/* ELEM이 테일인지 확인합니다. 테일이면 true, 아니면 false를 반환합니다. */
static inline bool is_tail(struct list_elem *elem)
{
    return elem != NULL && elem->prev != NULL && elem->next == NULL;
}

/* LIST를 빈 리스트로 초기화합니다. */
void list_init(struct list *list)
{
    ASSERT(list != NULL);
    list->head.prev = NULL;
    list->head.next = &list->tail;
    list->tail.prev = &list->head;
    list->tail.next = NULL;
}

/* LIST의 시작 부분을 반환합니다. */
struct list_elem *list_begin(struct list *list)
{
    ASSERT(list != NULL);
    return list->head.next;
}

/* ELEM이 속한 리스트에서 ELEM 다음 요소를 반환합니다. ELEM이 리스트의
   마지막 요소라면 리스트 테일을 반환합니다. ELEM이 리스트 테일 자체라면
   결과는 정의되지 않습니다. */
struct list_elem *list_next(struct list_elem *elem)
{
    ASSERT(is_head(elem) || is_interior(elem));
    return elem->next;
}

/* LIST의 테일을 반환합니다.

   list_end()는 리스트를 앞에서 뒤로 순회할 때 자주 사용됩니다.
   예제는 list.h 상단의 큰 주석을 참조하세요. */
struct list_elem *list_end(struct list *list)
{
    ASSERT(list != NULL);
    return &list->tail;
}

/* LIST를 뒤에서 앞으로 역순으로 순회하기 위한 LIST의 역방향 시작점을
 * 반환합니다. */
struct list_elem *list_rbegin(struct list *list)
{
    ASSERT(list != NULL);
    return list->tail.prev;
}

/* ELEM이 속한 리스트에서 ELEM 이전 요소를 반환합니다. ELEM이 리스트의
   첫 번째 요소라면 리스트 헤드를 반환합니다. ELEM이 리스트 헤드 자체라면
   결과는 정의되지 않습니다. */
struct list_elem *list_prev(struct list_elem *elem)
{
    ASSERT(is_interior(elem) || is_tail(elem));
    return elem->prev;
}

/* LIST의 헤드를 반환합니다.

   list_rend()는 리스트를 뒤에서 앞으로 역순으로 순회할 때 자주 사용됩니다.
   다음은 list.h 상단 예제를 따른 일반적인 사용법입니다:

   for (e = list_rbegin (&foo_list); e != list_rend (&foo_list);
   e = list_prev (e))
   {
   struct foo *f = list_entry (e, struct foo, elem);
   ...f로 무언가를 수행...
   }
   */
struct list_elem *list_rend(struct list *list)
{
    ASSERT(list != NULL);
    return &list->head;
}

/* LIST의 헤드를 반환합니다.

   list_head()는 리스트를 순회하는 다른 방식에 사용할 수 있습니다. 예:

   e = list_head (&list);
   while ((e = list_next (e)) != list_end (&list))
   {
   ...
   }
   */
struct list_elem *list_head(struct list *list)
{
    ASSERT(list != NULL);
    return &list->head;
}

/* LIST의 테일을 반환합니다. */
struct list_elem *list_tail(struct list *list)
{
    ASSERT(list != NULL);
    return &list->tail;
}

/* ELEM을 BEFORE 바로 앞에 삽입합니다. BEFORE는 내부 요소이거나 테일일 수
   있습니다. 후자의 경우는 list_push_back()과 동일합니다. */
void list_insert(struct list_elem *before, struct list_elem *elem)
{
    ASSERT(is_interior(before) || is_tail(before));
    ASSERT(elem != NULL);

    elem->prev = before->prev;
    elem->next = before;
    before->prev->next = elem;
    before->prev = elem;
}

/* FIRST부터 LAST까지(배타적)의 요소들을 현재 리스트에서 제거한 다음,
   BEFORE 바로 앞에 삽입합니다. BEFORE는 내부 요소이거나 테일일 수 있습니다. */
void list_splice(struct list_elem *before, struct list_elem *first,
                 struct list_elem *last)
{
    ASSERT(is_interior(before) || is_tail(before));
    if (first == last) return;
    last = list_prev(last);

    ASSERT(is_interior(first));
    ASSERT(is_interior(last));

    /* 현재 리스트에서 FIRST...LAST를 깔끔하게 제거합니다. */
    first->prev->next = last->next;
    last->next->prev = first->prev;

    /* 새 리스트에 FIRST...LAST를 연결합니다. */
    first->prev = before->prev;
    last->next = before;
    before->prev->next = first;
    before->prev = last;
}

/* ELEM을 LIST의 시작 부분에 삽입하여 LIST의 맨 앞이 되도록 합니다. */
void list_push_front(struct list *list, struct list_elem *elem)
{
    list_insert(list_begin(list), elem);
}

/* ELEM을 LIST의 끝 부분에 삽입하여 LIST의 맨 뒤가 되도록 합니다. */
void list_push_back(struct list *list, struct list_elem *elem)
{
    list_insert(list_end(list), elem);
}

/* ELEM을 리스트에서 제거하고 그 다음 요소를 반환합니다.
   ELEM이 리스트에 없으면 동작이 정의되지 않습니다.

   제거 후 ELEM을 리스트의 요소로 취급하는 것은 안전하지 않습니다.
   특히, 제거 후 ELEM에 대해 list_next()나 list_prev()를 사용하면
   정의되지 않은 동작이 발생합니다. 이는 리스트의 요소들을 제거하는
   순진한 루프가 실패함을 의미합니다:

 ** 이렇게 하지 마세요 **
 for (e = list_begin (&list); e != list_end (&list); e = list_next (e))
 {
 ...e로 무언가를 수행...
 list_remove (e);
 }
 ** 이렇게 하지 마세요 **

 리스트에서 요소들을 순회하고 제거하는 올바른 방법 중 하나입니다:

for (e = list_begin (&list); e != list_end (&list); e = list_remove (e))
{
...e로 무언가를 수행...
}

리스트의 요소들을 free()해야 한다면 더 보수적이어야 합니다.
이 경우에도 작동하는 다른 전략입니다:

while (!list_empty (&list))
{
struct list_elem *e = list_pop_front (&list);
...e로 무언가를 수행...
}
*/
struct list_elem *list_remove(struct list_elem *elem)
{
    ASSERT(is_interior(elem));
    elem->prev->next = elem->next;
    elem->next->prev = elem->prev;
    return elem->next;
}

/* LIST에서 맨 앞 요소를 제거하고 반환합니다.
   제거 전에 LIST가 비어있으면 동작이 정의되지 않습니다. */
struct list_elem *list_pop_front(struct list *list)
{
    struct list_elem *front = list_front(list);
    list_remove(front);
    return front;
}

/* LIST에서 맨 뒤 요소를 제거하고 반환합니다.
   제거 전에 LIST가 비어있으면 동작이 정의되지 않습니다. */
struct list_elem *list_pop_back(struct list *list)
{
    struct list_elem *back = list_back(list);
    list_remove(back);
    return back;
}

/* LIST의 맨 앞 요소를 반환합니다.
   LIST가 비어있으면 동작이 정의되지 않습니다. */
struct list_elem *list_front(struct list *list)
{
    ASSERT(!list_empty(list));
    return list->head.next;
}

/* LIST의 맨 뒤 요소를 반환합니다.
   LIST가 비어있으면 동작이 정의되지 않습니다. */
struct list_elem *list_back(struct list *list)
{
    ASSERT(!list_empty(list));
    return list->tail.prev;
}

/* LIST의 요소 개수를 반환합니다.
   요소 개수에 대해 O(n) 시간에 실행됩니다. */
size_t list_size(struct list *list)
{
    struct list_elem *e;
    size_t cnt = 0;

    for (e = list_begin(list); e != list_end(list); e = list_next(e)) cnt++;
    return cnt;
}

/* LIST가 비어있으면 true, 아니면 false를 반환합니다. */
bool list_empty(struct list *list)
{
    return list_begin(list) == list_end(list);
}

/* A와 B가 가리키는 `struct list_elem *'들을 교환합니다. */
static void swap(struct list_elem **a, struct list_elem **b)
{
    struct list_elem *t = *a;
    *a = *b;
    *b = t;
}

/* LIST의 순서를 뒤바꿉니다. */
void list_reverse(struct list *list)
{
    if (!list_empty(list))
    {
        struct list_elem *e;

        for (e = list_begin(list); e != list_end(list); e = e->prev)
            swap(&e->prev, &e->next);
        swap(&list->head.next, &list->tail.prev);
        swap(&list->head.next->prev, &list->tail.prev->next);
    }
}

/* 보조 데이터 AUX가 주어진 LESS에 따라 A부터 B까지(배타적)의 리스트 요소들이
   순서대로 정렬되어 있는 경우에만 true를 반환합니다. */
static bool is_sorted(struct list_elem *a, struct list_elem *b,
                      list_less_func *less, void *aux)
{
    if (a != b)
        while ((a = list_next(a)) != b)
            if (less(a, list_prev(a), aux)) return false;
    return true;
}

/* A에서 시작하여 B를 넘지 않는 범위에서, 보조 데이터 AUX가 주어진 LESS에 따라
   비내림차순으로 정렬된 리스트 요소들의 연속을 찾습니다. 연속의 (배타적) 끝을
   반환합니다. A부터 B까지(배타적)는 비어있지 않은 범위를 형성해야 합니다. */
static struct list_elem *find_end_of_run(struct list_elem *a,
                                         struct list_elem *b,
                                         list_less_func *less, void *aux)
{
    ASSERT(a != NULL);
    ASSERT(b != NULL);
    ASSERT(less != NULL);
    ASSERT(a != b);

    do
    {
        a = list_next(a);
    } while (a != b && !less(a, list_prev(a), aux));
    return a;
}

/* A0부터 A1B0까지(배타적)와 A1B0부터 B1까지(배타적)를 병합하여
   B1에서 끝나는(배타적) 결합된 범위를 형성합니다. 두 입력 범위는 모두
   비어있지 않고 보조 데이터 AUX가 주어진 LESS에 따라 비내림차순으로 정렬되어
   있어야 합니다. 출력 범위도 같은 방식으로 정렬됩니다. */
static void inplace_merge(struct list_elem *a0, struct list_elem *a1b0,
                          struct list_elem *b1, list_less_func *less, void *aux)
{
    ASSERT(a0 != NULL);
    ASSERT(a1b0 != NULL);
    ASSERT(b1 != NULL);
    ASSERT(less != NULL);
    ASSERT(is_sorted(a0, a1b0, less, aux));
    ASSERT(is_sorted(a1b0, b1, less, aux));

    while (a0 != a1b0 && a1b0 != b1)
        if (!less(a1b0, a0, aux))
            a0 = list_next(a0);
        else
        {
            a1b0 = list_next(a1b0);
            list_splice(a0, list_prev(a1b0), a1b0);
        }
}

/* 보조 데이터 AUX가 주어진 LESS에 따라 LIST를 정렬합니다.
   LIST의 요소 개수에 대해 O(n lg n) 시간과 O(1) 공간에서 실행되는
   자연스러운 반복적 병합 정렬을 사용합니다. */
void list_sort(struct list *list, list_less_func *less, void *aux)
{
    size_t output_run_cnt; /* 현재 패스에서 출력된 연속의 개수. */

    ASSERT(list != NULL);
    ASSERT(less != NULL);

    /* 리스트를 반복적으로 순회하면서 비내림차순 요소들의 인접한 연속을 병합하여
       하나의 연속만 남을 때까지 반복합니다. */
    do
    {
        struct list_elem *a0; /* 첫 번째 연속의 시작. */
        struct list_elem *a1b0; /* 첫 번째 연속의 끝, 두 번째 연속의 시작. */
        struct list_elem *b1; /* 두 번째 연속의 끝. */

        output_run_cnt = 0;
        for (a0 = list_begin(list); a0 != list_end(list); a0 = b1)
        {
            /* 각 반복은 하나의 출력 연속을 생성합니다. */
            output_run_cnt++;

            /* 비내림차순 요소들의 인접한 두 연속 A0...A1B0와 A1B0...B1을
             * 찾습니다. */
            a1b0 = find_end_of_run(a0, list_end(list), less, aux);
            if (a1b0 == list_end(list)) break;
            b1 = find_end_of_run(a1b0, list_end(list), less, aux);

            /* 연속들을 병합합니다. */
            inplace_merge(a0, a1b0, b1, less, aux);
        }
    } while (output_run_cnt > 1);

    ASSERT(is_sorted(list_begin(list), list_end(list), less, aux));
}

/* 보조 데이터 AUX가 주어진 LESS에 따라 정렬된 LIST의 적절한 위치에 ELEM을
   삽입합니다. LIST의 요소 개수에 대해 평균적으로 O(n) 시간에 실행됩니다. */
void list_insert_ordered(struct list *list, struct list_elem *elem,
                         list_less_func *less, void *aux)
{
    struct list_elem *e;

    ASSERT(list != NULL);
    ASSERT(elem != NULL);
    ASSERT(less != NULL);

    for (e = list_begin(list); e != list_end(list); e = list_next(e))
        if (less(elem, e, aux)) break;
    return list_insert(e, elem);
}

/* LIST를 순회하면서 보조 데이터 AUX가 주어진 LESS에 따라 동일한 인접 요소들의
   각 집합에서 첫 번째를 제외한 모든 요소를 제거합니다. DUPLICATES가 null이
   아니면 LIST에서 제거된 요소들이 DUPLICATES에 추가됩니다. */
void list_unique(struct list *list, struct list *duplicates,
                 list_less_func *less, void *aux)
{
    struct list_elem *elem, *next;

    ASSERT(list != NULL);
    ASSERT(less != NULL);
    if (list_empty(list)) return;

    elem = list_begin(list);
    while ((next = list_next(elem)) != list_end(list))
        if (!less(elem, next, aux) && !less(next, elem, aux))
        {
            list_remove(next);
            if (duplicates != NULL) list_push_back(duplicates, next);
        }
        else
            elem = next;
}

/* 보조 데이터 AUX가 주어진 LESS에 따라 LIST에서 가장 큰 값을 가진 요소를
   반환합니다. 최대값이 여러 개 있으면 리스트에서 더 앞에 나타나는 것을
   반환합니다. 리스트가 비어있으면 테일을 반환합니다. */
struct list_elem *list_max(struct list *list, list_less_func *less, void *aux)
{
    struct list_elem *max = list_begin(list);
    if (max != list_end(list))
    {
        struct list_elem *e;

        for (e = list_next(max); e != list_end(list); e = list_next(e))
            if (less(max, e, aux)) max = e;
    }
    return max;
}

/* 보조 데이터 AUX가 주어진 LESS에 따라 LIST에서 가장 작은 값을 가진 요소를
   반환합니다. 최소값이 여러 개 있으면 리스트에서 더 앞에 나타나는 것을
   반환합니다. 리스트가 비어있으면 테일을 반환합니다. */
struct list_elem *list_min(struct list *list, list_less_func *less, void *aux)
{
    struct list_elem *min = list_begin(list);
    if (min != list_end(list))
    {
        struct list_elem *e;

        for (e = list_next(min); e != list_end(list); e = list_next(e))
            if (less(e, min, aux)) min = e;
    }
    return min;
}
