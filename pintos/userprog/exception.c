#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "intrinsic.h"

/* 처리된 페이지 폴트 수 */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* 사용자 프로그램에 의해 발생할 수 있는 인터럽트들의 핸들러를 등록합니다.

   실제 Unix 계열 OS에서는 이러한 인터럽트들의 대부분이 [SV-386] 3-24와 3-25에
   설명된 바와 같이 시그널의 형태로 사용자 프로세스에게 전달되지만, 우리는
   시그널을 구현하지 않습니다. 대신, 단순히 사용자 프로세스를 종료시킵니다.

   페이지 폴트는 예외입니다. 여기서는 다른 예외들과 동일한 방식으로 처리되지만,
   가상 메모리를 구현하기 위해서는 변경이 필요합니다.

   이러한 예외들 각각의 설명은 [IA32-v3a] 5.15절 "Exception and Interrupt
   Reference"를 참조하세요. */
void
exception_init (void) {
	/* 이러한 예외들은 사용자 프로그램에 의해 명시적으로 발생시킬 수 있습니다.
	   예를 들어, INT, INT3, INTO, BOUND 명령어를 통해서 말이죠. 따라서,
	   DPL==3으로 설정하여 사용자 프로그램이 이러한 명령어들을 통해
	   예외를 호출할 수 있도록 합니다. */
	intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
	intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
	intr_register_int (5, 3, INTR_ON, kill,
			"#BR BOUND Range Exceeded Exception");

	/* 이러한 예외들은 DPL==0으로 설정되어 사용자 프로세스가 INT 명령어를 통해
	   호출하는 것을 방지합니다. 하지만 여전히 간접적으로 발생할 수 있습니다.
	   예를 들어, #DE는 0으로 나누기를 통해 발생할 수 있습니다. */
	intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
	intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
	intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
	intr_register_int (7, 0, INTR_ON, kill,
			"#NM Device Not Available Exception");
	intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
	intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
	intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
	intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
	intr_register_int (19, 0, INTR_ON, kill,
			"#XF SIMD Floating-Point Exception");

	/* 대부분의 예외들은 인터럽트가 켜진 상태에서 처리할 수 있습니다.
	   페이지 폴트의 경우 폴트 주소가 CR2에 저장되고 보존되어야 하므로
	   인터럽트를 비활성화해야 합니다. */
	intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* 예외 통계를 출력합니다. */
void
exception_print_stats (void) {
	printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* (아마도) 사용자 프로세스에 의해 발생된 예외의 핸들러입니다. */
static void
kill (struct intr_frame *f) {
	/* 이 인터럽트는 (아마도) 사용자 프로세스에 의해 발생된 것입니다.
	   예를 들어, 프로세스가 매핑되지 않은 가상 메모리에 접근하려고 했을 수
	   있습니다 (페이지 폴트). 현재는 단순히 사용자 프로세스를 종료시킵니다.
	   나중에는 커널에서 페이지 폴트를 처리하고 싶을 것입니다. 실제 Unix 계열
	   운영체제는 대부분의 예외를 시그널을 통해 프로세스에게 다시 전달하지만,
	   우리는 시그널을 구현하지 않습니다. */

	/* 인터럽트 프레임의 코드 세그먼트 값은 예외가 어디서 발생했는지 알려줍니다. */
	switch (f->cs) {
		case SEL_UCSEG:
        /* 사용자의 코드 세그먼트이므로 예상한 대로 사용자 예외입니다.
           사용자 프로세스를 종료시킵니다. */
			printf ("%s: dying due to interrupt %#04llx (%s).\n",
					thread_name (), f->vec_no, intr_name (f->vec_no));
			intr_dump_frame (f);
			thread_exit ();

		case SEL_KCSEG:
        /* 커널의 코드 세그먼트이므로 커널 버그를 나타냅니다.
           커널 코드는 예외를 발생시키면 안 됩니다. (페이지 폴트가 커널
           예외를 발생시킬 수 있지만--여기에 도달하면 안 됩니다.)
           이 점을 명확히 하기 위해 커널을 패닉시킵니다. */
			intr_dump_frame (f);
			PANIC ("Kernel bug - unexpected interrupt in kernel");

		default:
        /* 다른 코드 세그먼트? 발생하면 안 됩니다. 커널을 패닉시킵니다. */
			printf ("Interrupt %#04llx (%s) in unknown segment %04x\n",
					f->vec_no, intr_name (f->vec_no), f->cs);
			thread_exit ();
	}
}

/* 페이지 폴트 핸들러입니다. 이것은 가상 메모리를 구현하기 위해 채워져야 하는
   뼈대입니다. 프로젝트 2의 일부 솔루션들도 이 코드를 수정해야 할 수 있습니다.

   진입 시점에서 폴트가 발생한 주소는 CR2(Control Register 2)에 있고,
   exception.h의 PF_* 매크로에 설명된 형식으로 포맷된 폴트에 대한 정보는
   F의 error_code 멤버에 있습니다. 여기의 예제 코드는 해당 정보를 파싱하는
   방법을 보여줍니다. 이 둘에 대한 더 많은 정보는 [IA32-v3a] 5.15절
   "Exception and Interrupt Reference"의 "Interrupt 14--Page Fault Exception (#PF)"
   설명에서 찾을 수 있습니다. */
static void
page_fault (struct intr_frame *f) {
	bool not_present;  /* True: 존재하지 않는 페이지, false: 읽기 전용 페이지에 쓰기. */
	bool write;        /* True: 접근이 쓰기였음, false: 접근이 읽기였음. */
	bool user;         /* True: 사용자에 의한 접근, false: 커널에 의한 접근. */
	void *fault_addr;  /* 폴트 주소. */

	/* 폴트 주소를 얻습니다. 이는 폴트를 발생시킨 접근의 대상이 된 가상 주소입니다.
	   이것은 코드나 데이터를 가리킬 수 있습니다. 이것이 반드시 폴트를 발생시킨
	   명령어의 주소는 아닙니다 (그것은 f->rip입니다). */


	fault_addr = (void *) rcr2();

	/* 인터럽트를 다시 켭니다 (CR2가 변경되기 전에 읽을 수 있도록 보장하기 위해
	   잠시 꺼져 있었습니다). */
	intr_enable ();


	/* 원인을 결정합니다. */
	not_present = (f->error_code & PF_P) == 0;
	write = (f->error_code & PF_W) != 0;
	user = (f->error_code & PF_U) != 0;

#ifdef VM
/* 프로젝트 3 이후를 위한 것입니다. */
	if (vm_try_handle_fault (f, fault_addr, user, write, not_present))
		return;
#endif

	/* 페이지 폴트를 카운트합니다. */
	page_fault_cnt++;

	if (user) exit(-1);
	else {
		/* 폴트가 실제 폴트라면, 정보를 보여주고 종료합니다. */
		printf ("Page fault at %p: %s error %s page in %s context.\n",
				fault_addr,
				not_present ? "not present" : "rights violation",
				write ? "writing" : "reading",
				user ? "user" : "kernel");
		kill (f);
	}
}

