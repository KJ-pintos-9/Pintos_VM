#include <console.h>
#include <debug.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "devices/serial.h"
#include "threads/init.h"
#include "threads/interrupt.h"

/* OS를 중단시키고 소스 파일 이름, 줄 번호, 함수 이름과
   사용자 지정 메시지를 출력합니다. */
void debug_panic(const char *file, int line, const char *function,
                 const char *message, ...)
{
    static int level;
    va_list args;

    intr_disable();
    console_panic();

    level++;
    if (level == 1)
    {
        printf("Kernel PANIC at %s:%d in %s(): ", file, line, function);

        va_start(args, message);
        vprintf(message, args);
        printf("\n");
        va_end(args);

        debug_backtrace();
    }
    else if (level == 2)
        printf("Kernel PANIC recursion at %s:%d in %s().\n", file, line,
               function);
    else
    {
        /* 아무것도 출력하지 않습니다: 아마도 그래서 재귀가 발생했을 것입니다.
         */
    }

    serial_flush();
    if (power_off_when_done) power_off();
    for (;;)
        ;
}
