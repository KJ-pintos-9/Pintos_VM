#include <debug.h>
#include <string.h>

/* SRC에서 DST로 SIZE 바이트를 복사합니다. 겹치지 않아야 합니다.
   DST를 반환합니다. */
void *memcpy(void *dst_, const void *src_, size_t size)
{
    unsigned char *dst = dst_;
    const unsigned char *src = src_;

    ASSERT(dst != NULL || size == 0);
    ASSERT(src != NULL || size == 0);

    while (size-- > 0) *dst++ = *src++;

    return dst_;
}

/* SRC에서 DST로 SIZE 바이트를 복사합니다. 겹치는 것이 허용됩니다.
   DST를 반환합니다. */
void *memmove(void *dst_, const void *src_, size_t size)
{
    unsigned char *dst = dst_;
    const unsigned char *src = src_;

    ASSERT(dst != NULL || size == 0);
    ASSERT(src != NULL || size == 0);

    if (dst < src)
    {
        while (size-- > 0) *dst++ = *src++;
    }
    else
    {
        dst += size;
        src += size;
        while (size-- > 0) *--dst = *--src;
    }

    return dst;
}

/* A와 B에서 SIZE 바이트의 두 블록에서 첫 번째로 다른 바이트를 찾습니다.
   A의 바이트가 더 크면 양수 값을, B의 바이트가 더 크면 음수 값을,
   블록 A와 B가 같으면 0을 반환합니다. */
int memcmp(const void *a_, const void *b_, size_t size)
{
    const unsigned char *a = a_;
    const unsigned char *b = b_;

    ASSERT(a != NULL || size == 0);
    ASSERT(b != NULL || size == 0);

    for (; size-- > 0; a++, b++)
        if (*a != *b) return *a > *b ? +1 : -1;
    return 0;
}

/* 문자열 A와 B에서 첫 번째로 다른 문자를 찾습니다.
   A의 문자(unsigned char로)가 더 크면 양수 값을, B의 문자(unsigned char로)가 더
   크면 음수 값을, 문자열 A와 B가 같으면 0을 반환합니다. */
int strcmp(const char *a_, const char *b_)
{
    const unsigned char *a = (const unsigned char *) a_;
    const unsigned char *b = (const unsigned char *) b_;

    ASSERT(a != NULL);
    ASSERT(b != NULL);

    while (*a != '\0' && *a == *b)
    {
        a++;
        b++;
    }

    return *a < *b ? -1 : *a > *b;
}

/* BLOCK에서 시작하는 첫 번째 SIZE 바이트에서 CH의 첫 번째 발생을 가리키는
   포인터를 반환합니다. CH가 BLOCK에서 발생하지 않으면 null 포인터를 반환합니다.
 */
void *memchr(const void *block_, int ch_, size_t size)
{
    const unsigned char *block = block_;
    unsigned char ch = ch_;

    ASSERT(block != NULL || size == 0);

    for (; size-- > 0; block++)
        if (*block == ch) return (void *) block;

    return NULL;
}

/* STRING에서 C의 첫 번째 발생을 찾아 반환하거나, C가 STRING에 나타나지 않으면
   null 포인터를 반환합니다. C == '\0'이면 STRING 끝의 null 종료자를 가리키는
   포인터를 반환합니다. */
char *strchr(const char *string, int c_)
{
    char c = c_;

    ASSERT(string);

    for (;;)
        if (*string == c)
            return (char *) string;
        else if (*string == '\0')
            return NULL;
        else
            string++;
}

/* STOP에 없는 문자들로 구성된 STRING의 초기 부분 문자열의 길이를 반환합니다. */
size_t strcspn(const char *string, const char *stop)
{
    size_t length;

    for (length = 0; string[length] != '\0'; length++)
        if (strchr(stop, string[length]) != NULL) break;
    return length;
}

/* STRING에서 STOP에도 있는 첫 번째 문자를 가리키는 포인터를 반환합니다.
   STRING의 어떤 문자도 STOP에 없으면 null 포인터를 반환합니다. */
char *strpbrk(const char *string, const char *stop)
{
    for (; *string != '\0'; string++)
        if (strchr(stop, *string) != NULL) return (char *) string;
    return NULL;
}

/* STRING에서 C의 마지막 발생을 가리키는 포인터를 반환합니다.
   C가 STRING에서 발생하지 않으면 null 포인터를 반환합니다. */
char *strrchr(const char *string, int c_)
{
    char c = c_;
    const char *p = NULL;

    for (; *string != '\0'; string++)
        if (*string == c) p = string;
    return (char *) p;
}

/* SKIP에 있는 문자들로 구성된 STRING의 초기 부분 문자열의 길이를 반환합니다. */
size_t strspn(const char *string, const char *skip)
{
    size_t length;

    for (length = 0; string[length] != '\0'; length++)
        if (strchr(skip, string[length]) == NULL) break;
    return length;
}

/* HAYSTACK 내에서 NEEDLE의 첫 번째 발생을 가리키는 포인터를 반환합니다.
   NEEDLE이 HAYSTACK 내에 존재하지 않으면 null 포인터를 반환합니다. */
char *strstr(const char *haystack, const char *needle)
{
    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);

    if (haystack_len >= needle_len)
    {
        size_t i;

        for (i = 0; i <= haystack_len - needle_len; i++)
            if (!memcmp(haystack + i, needle, needle_len))
                return (char *) haystack + i;
    }

    return NULL;
}

/* DELIMITERS로 구분된 토큰으로 문자열을 분할합니다.
   이 함수가 처음 호출될 때 S는 토큰화할 문자열이어야 하고,
   이후 호출에서는 null 포인터여야 합니다.
   SAVE_PTR은 토큰화기의 위치를 추적하는 데 사용되는 `char *' 변수의 주소입니다.
   매번 반환값은 문자열의 다음 토큰이거나, 남은 토큰이 없으면 null 포인터입니다.

   이 함수는 여러 인접한 구분자를 단일 구분자로 처리합니다.
   반환되는 토큰은 절대 길이가 0이 아닙니다.
   DELIMITERS는 단일 문자열 내에서 한 번의 호출에서 다음 호출로 변경될 수
있습니다.

   strtok_r()은 문자열 S를 수정하여 구분자를 null 바이트로 변경합니다.
   따라서 S는 수정 가능한 문자열이어야 합니다. 특히 문자열 리터럴은
   이전 버전과의 호환성을 위해 `const'가 아니지만 C에서는 수정할 수 *없습니다*.

   사용 예제:

   char s[] = "  String to  tokenize. ";
   char *token, *save_ptr;

   for (token = strtok_r (s, " ", &save_ptr); token != NULL;
   token = strtok_r (NULL, " ", &save_ptr))
   printf ("'%s'\n", token);

출력:

'String'
'to'
'tokenize.'
*/
char *strtok_r(char *s, const char *delimiters, char **save_ptr)
{
    char *token;

    ASSERT(delimiters != NULL);
    ASSERT(save_ptr != NULL);

    /* S가 null이 아니면 거기서 시작합니다.
       S가 null이면 저장된 위치에서 시작합니다. */
    if (s == NULL) s = *save_ptr;
    ASSERT(s != NULL);

    /* 현재 위치의 모든 DELIMITERS를 건너뜁니다. */
    while (strchr(delimiters, *s) != NULL)
    {
        /* strchr()은 null 바이트를 검색하면 항상 null이 아닌 값을 반환합니다.
           모든 문자열에는 null 바이트가 포함되어 있기 때문입니다(끝에). */
        if (*s == '\0')
        {
            *save_ptr = s;
            return NULL;
        }

        s++;
    }

    /* 문자열 끝까지 DELIMITERS가 아닌 문자들을 건너뜁니다. */
    token = s;
    while (strchr(delimiters, *s) == NULL) s++;
    if (*s != '\0')
    {
        *s = '\0';
        *save_ptr = s + 1;
    }
    else
        *save_ptr = s;
    return token;
}

/* DST의 SIZE 바이트를 VALUE로 설정합니다. */
void *memset(void *dst_, int value, size_t size)
{
    unsigned char *dst = dst_;

    ASSERT(dst != NULL || size == 0);

    while (size-- > 0) *dst++ = value;

    return dst_;
}

/* STRING의 길이를 반환합니다. */
size_t strlen(const char *string)
{
    const char *p;

    ASSERT(string);

    for (p = string; *p != '\0'; p++) continue;
    return p - string;
}

/* STRING이 MAXLEN 문자보다 짧으면 실제 길이를 반환합니다.
   그렇지 않으면 MAXLEN을 반환합니다. */
size_t strnlen(const char *string, size_t maxlen)
{
    size_t length;

    for (length = 0; string[length] != '\0' && length < maxlen; length++)
        continue;
    return length;
}

/* 문자열 SRC를 DST에 복사합니다. SRC가 SIZE - 1 문자보다 길면
   SIZE - 1 문자만 복사됩니다. SIZE가 0이 아닌 한 DST에는 항상 null 종료자가
쓰여집니다. null 종료자를 포함하지 않은 SRC의 길이를 반환합니다.

   strlcpy()는 표준 C 라이브러리에 없지만 점점 인기가 높아지는 확장입니다.
   strlcpy()에 대한 정보는
http://www.courtesan.com/todd/papers/strlcpy.html을 참조하세요.
information on strlcpy(). */
size_t strlcpy(char *dst, const char *src, size_t size)
{
    size_t src_len;

    ASSERT(dst != NULL);
    ASSERT(src != NULL);

    src_len = strlen(src);
    if (size > 0)
    {
        size_t dst_len = size - 1;
        if (src_len < dst_len) dst_len = src_len;
        memcpy(dst, src, dst_len);
        dst[dst_len] = '\0';
    }
    return src_len;
}

/* 문자열 SRC를 DST에 연결합니다. 연결된 문자열은 SIZE - 1 문자로 제한됩니다.
   SIZE가 0이 아닌 한 DST에는 항상 null 종료자가 쓰여집니다.
   충분한 공간이 있다고 가정했을 때 연결된 문자열이 가졌을 길이를
반환합니다(null 종료자 제외).

   strlcat()는 표준 C 라이브러리에 없지만 점점 인기가 높아지는 확장입니다.
   strlcpy()에 대한 정보는
http://www.courtesan.com/todd/papers/strlcpy.html을 참조하세요. */
size_t strlcat(char *dst, const char *src, size_t size)
{
    size_t src_len, dst_len;

    ASSERT(dst != NULL);
    ASSERT(src != NULL);

    src_len = strlen(src);
    dst_len = strlen(dst);
    if (size > 0 && dst_len < size)
    {
        size_t copy_cnt = size - dst_len - 1;
        if (src_len < copy_cnt) copy_cnt = src_len;
        memcpy(dst + dst_len, src, copy_cnt);
        dst[dst_len + copy_cnt] = '\0';
    }
    return src_len + dst_len;
}
