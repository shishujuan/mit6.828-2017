# Exercize 1

需要修改 mem_init 分配和映射envs数组，映射地址是 UENVS，权限是PTE_U，完成后可以看到 check_kern_pgdir() 通过测试。

```
// Make 'envs' point to an array of size 'NENV' of 'struct Env'.
// LAB 3: Your code here.
envs = (struct Env *)boot_alloc(sizeof(struct Env) * NENV);
memset(envs, 0, sizeof(struct Env) * NENV);
 
//////////////////////////////////////////////////////////////////////
// Now that we've allocated the initial kernel data structures, we set
//    - the new image at UENVS  -- kernel R, user R
//    - envs itself -- kernel RW, user NONE
// LAB 3: Your code here.
boot_map_region(kern_pgdir, UENVS, PTSIZE, PADDR(envs), PTE_U);
```

# Exercize 2

需要完成 env_init(), env_setup_vm(), region_alloc(), load_icode(), env_create(), env_run() 这几个函数。

### env_init()
如在用户环境的分析中提到，env_init()主要负责初始化 `struct Env`的空闲链表，跟上一章的pages空闲链表类似，注意初始化顺序。

```
void
env_init(void)
{
    // Set up envs array
    // LAB 3: Your code here.
    for (int i = NENV-1; i >= 0; i--) {
        struct Env *e = &envs[i];
        e->env_id = 0;
        e->env_status = ENV_FREE;
        e->env_link = env_free_list;
        env_free_list = e;
    }   

    // Per-CPU part of the initialization
    env_init_percpu();
}

```

### env_setup_vm()
这个函数主要功能是分配好页目录，并设置运行进程的 env_pgdir 字段，注意，env_pgdir是虚拟地址。不要忘记将 p->pp_ref++， 因为在env_free()的时候会decref的。所有的进程在UTOP之上的页目录表(除了UVPT之外)都跟kernel是一样的，所以可以直接用memcpy将kern_pgdir的页目录表内容拷贝过来，然后单独设置UVPT这个页目录项即可。

```
static int
env_setup_vm(struct Env *e)
{
    int i;
    struct PageInfo *p = NULL;

    // Allocate a page for the page directory
    if (!(p = page_alloc(ALLOC_ZERO)))
        return -E_NO_MEM;

    // Now, set e->env_pgdir and initialize the page directory.
    // LAB 3: Your code here.
    p->pp_ref++;
    e->env_pgdir = (pde_t *)page2kva(p);
    memcpy(e->env_pgdir, kern_pgdir, PGSIZE);

    // UVPT maps the env's own page table read-only.
    // Permissions: kernel R, user R
    e->env_pgdir[PDX(UVPT)] = PADDR(e->env_pgdir) | PTE_P | PTE_U;

    return 0;
}
```

### region_alloc()
为用户程序分配和映射内存，该函数只在load_icode()中调用，需要注意边界条件。

```
static void
region_alloc(struct Env *e, void *va, size_t len)
{
    void *begin = ROUNDDOWN(va, PGSIZE), *end = ROUNDUP(va + len, PGSIZE);
    for (; begin < end; begin += PGSIZE) {
        struct PageInfo *p = page_alloc(0);
        if (!p) panic("env region_alloc failed");
        page_insert(e->env_pgdir, p, begin, PTE_W | PTE_U);
    }   
}
```

### load_icode()
加载用户程序二进制代码。该函数会设置进程的tf_eip值为 elf->e_entry，并分配映射用户栈内存。注意，在调用 `region_alloc` 分配映射内存前，需要先设置cr3寄存器内容为进程的页目录物理地址，设置完成后再设回 kern_pgdir的物理地址。

```
static void
load_icode(struct Env *e, uint8_t *binary)
{
    struct Elf *env_elf;
    struct Proghdr *ph, *eph;
    env_elf = (struct Elf*)binary;
    ph = (struct Proghdr*)((uint8_t*)(env_elf) + env_elf->e_phoff);
    eph = ph + env_elf->e_phnum;

    lcr3(PADDR(e->env_pgdir));

    for (; ph < eph; ph++) {
        if(ph->p_type == ELF_PROG_LOAD) {
            region_alloc(e, (void *)ph->p_va, ph->p_memsz);
            memcpy((void*)ph->p_va, (void *)(binary+ph->p_offset), ph->p_filesz);
            memset((void*)(ph->p_va + ph->p_filesz), 0, ph->p_memsz-ph->p_filesz);
        }
    }

    e->env_tf.tf_eip = env_elf->e_entry;
    lcr3(PADDR(kern_pgdir));

    // Now map one page for the program's initial stack
    // at virtual address USTACKTOP - PGSIZE.
    region_alloc(e, (void *)(USTACKTOP-PGSIZE), PGSIZE);
}
```

### env_create()
首先调用env_alloc分配 struct Env结构以及页目录，然后调用load_icode加载进程代码。

```
void
env_create(uint8_t *binary, enum EnvType type)
{
    struct Env *e;
    env_alloc(&e, 0);
    e->env_type = type;
    load_icode(e, binary);
}
```

### env_run()
在用户模式运行用户进程。

```
void
env_run(struct Env *e)
{
    // panic("env_run not yet implemented");
    if (curenv && curenv->env_status == ENV_RUNNING) {
        curenv->env_status = ENV_RUNNABLE;
    }
    curenv = e;
    curenv->env_status = ENV_RUNNING;
    curenv->env_runs++;
    lcr3(PADDR(curenv->env_pgdir));
    env_pop_tf(&curenv->env_tf);
}
```

做完exercize 2后，会发现提示`triple fault`，类似下面这样报错。这是因为用户程序`user/hello.c`中调用了 cprintf输出 `hello world`，会用到系统调用指令`int 0x30`。而此时系统并没有设置好中断向量表，当CPU收到系统调用中断时，发现没有处理程序可以处理，于是会报一个`general protection`异常，这就产生了`double fault exception`，而接着CPU发现它也没法处理`general protection`异常，于是报`triple fault`。通常，遇到这种情况CPU会复位系统会不断重启，为了方便调试内核，JOS用的QEMU打过补丁，从而没有不断重启，而是用一条`triple fault`的提示消息代替。

```
6828 decimal is 15254 octal!
Physical memory: 131072K available, base = 640K, extended = 130432K
boot_alloc, nextfree:f017e000
......
EAX=00000000 EBX=00000000 ECX=0000000d EDX=eebfde88
ESI=00000000 EDI=00000000 EBP=eebfde60 ESP=eebfde54
EIP=00800add EFL=00000092 [--S-A--] CPL=3 II=0 A20=1 SMM=0 HLT=0
ES =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
CS =001b 00000000 ffffffff 00cffa00 DPL=3 CS32 [-R-]
SS =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
DS =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
FS =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
GS =0023 00000000 ffffffff 00cff300 DPL=3 DS   [-WA]
LDT=0000 00000000 00000000 00008200 DPL=0 LDT
TR =0028 f017da20 00000067 00408900 DPL=0 TSS32-avl
GDT=     f011b320 0000002f
IDT=     f017d200 000007ff
CR0=80050033 CR2=00000000 CR3=00044000 CR4=00000000
DR0=00000000 DR1=00000000 DR2=00000000 DR3=00000000 
DR6=ffff0ff0 DR7=00000400
EFER=0000000000000000
Triple fault.  Halting for inspection via QEMU monitor.
```

为了保证你的代码是正确的，最好在`make qemu-gdb`后 `b env_pop_tf`设置下断点，看看用户进程是否真的开始运行了，如果代码正确的话则输出应该如下所示。

```
(gdb) b env_pop_tf
Breakpoint 1 at 0xf010383e: file kern/env.c, line 462.
(gdb) c
Continuing.
The target architecture is assumed to be i386
=> 0xf010383e <env_pop_tf>:	push   %ebp

Breakpoint 1, env_pop_tf (tf=0xf01bf000) at kern/env.c:462
462	{
(gdb) s
=> 0xf0103844 <env_pop_tf+6>:	mov    0x8(%ebp),%esp
463		asm volatile(
(gdb) s
=> 0x800020:	cmp    $0xeebfe000,%esp
0x00800020 in ?? ()
(gdb) si
=> 0x800026:	jne    0x80002c
0x00800026 in ?? ()
```

接下来我们来分析下到目前为止为了实现地址映射，我们用掉了free_page_list中哪些内存页以及对应的内存了。

- 在lab 2中我们为映射 [UPAGES, UPAGES+4M) 分配页表，用掉空闲链表free_page_list中的一页，其在内核页目录表表项为 `0xef000000 / 4M = 956`。
- 还有本实验为映射 [UENVS, UENVS + 4M) 分配页表，用掉一页内存，其页目录项为 `0xeec00000 / 4M = 955`。
- 此外，还有内核栈 [KSTACKTOP-KSTKSIZE, KSTACKTOP) 的映射，用掉一页内存，页目录项为 `efff8000 / 4M = 959`。
- 剩下就是对 [KERNBASE, 2**32-KERNBASE)映射，用掉64页内存，对应的页目录项为 `960-1023`。
- 到目前为止，除了用户进程占用的内存外，一共用掉了 1+1+1+64=67 页内存，用户进程使用内存大小跟程序大小有关。

由于检查代码会分配和释放页面，所以这里分配的页的顺序不一定是按数字顺序来的，因为释放的页面会被加入到free_page_list头部。这个我们可以进入系统来确认下是不是真的这样：

```
env:0 pgno:68 env_pgdir_addr:f01c005c,val:f0044000 kern_pgdir_addr:f017eea8,val:f017f000
```
从打印的内容可以知道内核页目录表位于虚拟地址 0xf017f000，物理地址 0x17f000处。接下来，我们从 0xf017f000处开始查看上面提到的页目录项的值，看看是否对应。先看第955和956项，可以看到955项分配了第2页内存，而956项分配了第3页内存。957项存储的是页目录地址 0x17f005(末位的5是一些标志位)，959项则是分配了第1页内存作为页表。从960项到1024则是用于的KERNBASE之上的映射。我们也可以看到用户进程页目录表项在UTOP之上跟内核页目录表是一样的，唯一例外是 UVPT对应的目录项，指向的是各自的的页目录地址。

看页目录项的标志位低3位是7，这是因为我们在`pgdir_walk()`中将页目录的权限设置的比较大，`*pde = page2pa(page) | PTE_P | PTE_U | PTE_W;`，因为x86的MMU会检查页目录项和页表项，所以页目录权限大一点是没问题的。

而我们也可以继续深入去看每个页表项的初始化情况，如我们想看下UPAGES映射的第3页的页表项，我们知道UPAGES映射到物理内存pages值 0x180000 处，查看内存数据为0x00180005，确认没错，其中页表项标志位5表示用户可读(PTE_P|PTE_U)。譬如[KSTACKTOP-KTSIZE, KSTACKTOP)的映射，它的页目录项为0x1007，在第一页。用命令看第一页对应的页表项可以看到页表项从`1016-1023`映射了8页。

注意，有些虚拟地址是映射到同一页物理内存的，只是映射的权限不同。比如 UPAGES 在我的测试环境 0xef000000 映射的物理内存页为0x180页(0x00180005，权限5是PTE_P|PTE_U)，而我们在[KERNBASE, 2**32-KERNBASE)区间的虚拟地址 0xf0004600 也是映射到物理内存 0x180页(0x00180063，末位标识3表示PTE_P|PTE_W）。

```
## 查看页目录项
(gdb) x /16x 0xf017fee0
0xf017fee0:	0x00000000	0x00000000	0x00000000	0x00002007
0xf017fef0:	0x00003007	0x0017f005	0x00000000	0x00001007
0xf017ff00:	0x00004027	0x00005027	0x00006027	0x00007027
0xf017ff10:	0x00008027	0x00009027	0x0000a027	0x0000b027

# KSTACKTOP-PGSIZE映射的8页
(gdb) x /8x 0xf0001fe0
0xf0001fe0:	0x00112003	0x00113003	0x00114003	0x00115003
0xf0001ff0:	0x00116003	0x00117003	0x00118003	0x00119003

## 查看UPAGES对应的页表项
(gdb) x /8x 0xf0003000
0xf0003000:	0x00180005	0x00181005	0x00182005	0x00183005
0xf0003010:	0x00184005	0x00185005	0x00186005	0x00187005

## KERNBASE上与UPAGES映射的同样的物理页
(gdb) x /4x 0xf0004600
0xf0004600:	0x00180063	0x00181023	0x00182023	0x00183023
```

# Exercize 3
学习异常和中断的理论知识。https://pdos.csail.mit.edu/6.828/2017/readings/i386/c09.htm。

# Exercize 4

完成中断向量表初始化以及异常/中断处理，需要修改 `kern/trapentry.S` 和 `kern/trap.c`文件。在 `trap_init()`中使用SETGATE来初始化中断向量，在`trapentry.S`中通过 `TRAPHANDLER`和`TRAPHANDLER_NOEC`初始化中断处理函数。

```
void
trap_init(void)
{
    extern struct Segdesc gdt[];

    // LAB 3: Your code here.
    void handler0();
    void handler1();
    void handler2();
    void handler3();
    void handler4();
    void handler5();
    void handler6();
    void handler7();
    void handler8();
    void handler10();
    void handler11();
    void handler12();
    void handler13();
    void handler14();
    void handler15();
    void handler16();
    void handler48();

    SETGATE(idt[T_DIVIDE], 0, GD_KT, handler0, 0); 
    SETGATE(idt[T_DEBUG], 0, GD_KT, handler1, 0); 
    SETGATE(idt[T_NMI], 0, GD_KT, handler2, 0); 

    // T_BRKPT DPL 3
    SETGATE(idt[T_BRKPT], 0, GD_KT, handler3, 3); 

    SETGATE(idt[T_OFLOW], 0, GD_KT, handler4, 0); 
    SETGATE(idt[T_BOUND], 0, GD_KT, handler5, 0); 
    SETGATE(idt[T_ILLOP], 0, GD_KT, handler6, 0); 
    SETGATE(idt[T_DEVICE], 0, GD_KT, handler7, 0); 
    SETGATE(idt[T_DBLFLT], 0, GD_KT, handler8, 0); 
    SETGATE(idt[T_TSS], 0, GD_KT, handler10, 0); 
    SETGATE(idt[T_SEGNP], 0, GD_KT, handler11, 0); 
    SETGATE(idt[T_STACK], 0, GD_KT, handler12, 0); 
    SETGATE(idt[T_GPFLT], 0, GD_KT, handler13, 0); 
    SETGATE(idt[T_PGFLT], 0, GD_KT, handler14, 0); 
    SETGATE(idt[T_FPERR], 0, GD_KT, handler16, 0); 

    // T_SYSCALL DPL 3
    SETGATE(idt[T_SYSCALL], 0, GD_KT, handler48, 3); 

    // Per-CPU setup 
    trap_init_percpu();
}
```

trapentry.S中添加代码如下，前面是常规操作，_alltraps这段汇编要注意下，段寄存器ds，es在mov指令中不支持立即数，所以用到ax寄存器中转下数据。在理论分析时我们提到，由用户模式发生中断进入内核时，CPU会切换到内核栈，并压入旧的 SS, ESP, EFLAGS, CS, EIP寄存器的值。接着，执行中断处理程序。这里，会先通过 `TRAPHANDLER`压入中断向量以及错误码(如果有)，然后在_alltraps中压入旧的DS, ES寄存器以及通用寄存器的值，接着将DS, ES寄存器设置为GD_KD，并将此时 ESP寄存器的值压入到内核栈中作为trap函数的参数，然后才调用trap(tf)函数。


```
/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

TRAPHANDLER_NOEC(handler0, T_DIVIDE)
TRAPHANDLER_NOEC(handler1, T_DEBUG)
TRAPHANDLER_NOEC(handler2, T_NMI)
TRAPHANDLER_NOEC(handler3, T_BRKPT)
TRAPHANDLER_NOEC(handler4, T_OFLOW)
TRAPHANDLER_NOEC(handler5, T_BOUND)
TRAPHANDLER_NOEC(handler6, T_ILLOP)
TRAPHANDLER(handler7, T_DEVICE)
TRAPHANDLER_NOEC(handler8, T_DBLFLT)
TRAPHANDLER(handler10, T_TSS)
TRAPHANDLER(handler11, T_SEGNP)
TRAPHANDLER(handler12, T_STACK)
TRAPHANDLER(handler13, T_GPFLT)
TRAPHANDLER(handler14, T_PGFLT)
TRAPHANDLER_NOEC(handler16, T_FPERR)
TRAPHANDLER_NOEC(handler48, T_SYSCALL)

/*
 * Lab 3: Your code here for _alltraps
 */
_alltraps:
        pushl %ds 
        pushl %es 
        pushal
        movw $GD_KD, %ax
        movw %ax, %ds 
        movw %ax, %es 
        pushl %esp
        call trap /*never return*/

1:jmp 1b
```

做这些处理的作用是在内核栈中构造Trapframe的结构，这样在_alltraps之后，`trap(Trapframe tf)`中参数tf指向的内核栈，而栈中内容正好是一个完整的Trapframe结构。


```
 低地址                                                       高地址
 +---------------------------------------------------------------+             
 |regs | es | ds | trapno | errno | eip | cs | eflags | esp | ss |
 +---------------------------------------------------------------+
```

完成了 Exercize 4之后，我们现在`make qemu`可以看到没有报`triple fault`了，但是由于 `user_hello`运行时用了`int 0x30`触发了中断，而我们的trap()函数并没有针对中断做处理，于是会销毁该用户进程并进入 monitor()。而用`make grade`可以看到`divzero, softint, badsegment`这几个测试通过了。

```
Incoming TRAP frame at 0xefffffbc
TRAP frame at 0xf01c0000
  edi  0x00000000
  esi  0x00000000
  ebp  0xeebfde60
  oesp 0xefffffdc
  ebx  0x00000000
  edx  0xeebfde88
  ecx  0x0000000d
  eax  0x00000000
  es   0x----0023
  ds   0x----0023
  trap 0x00000030 System call
  err  0x00000000
  eip  0x00800adf
  cs   0x----001b
  flag 0x00000092
  esp  0xeebfde54
  ss   0x----0023
[00001000] free env 00001000
Destroyed the only environment - nothing more to do!
Welcome to the JOS kernel monitor!
Type 'help' for a list of commands.
K> 
```

当然这里有很多重复代码，其中的challenge就等后面有时间再做了，需要对汇编更熟悉一点。另外这里两个问题：

### Question 1
为什么要对每个中断向量设置不同的中断处理函数，而不是放到一个函数里面统一处理？

答：这是为了区分不同的异常/中断类型，TRAPHANDLER在栈中压入了中断向量trapno和错误码errno，在以方便后面根据异常/中断类型做对应处理。

### Question 2
为什么`user/softint.c`程序调用的是`int $14`会报13异常(general protection fault)？

答：这是因为我们在SETGATE中对中断向量14设置的DPL为0，从而由于用户程序CPL=3，触发了13异常。如果要允许，可以设置中断向量14的DPL为3，但是我们是不希望用户程序来操作内存的。

# Exercize 5-6
作业5，6是在trap_dispatch中对page fault异常和breakpoint异常进行处理。比较简单，代码如下，完成后`make grade`可以看到 `faultread、faultreadkernel、faultwrite、faultwritekernel，breakpoint` `通过测试。

```
static void
trap_dispatch(struct Trapframe *tf)
{
    // Handle processor exceptions.
    // LAB 3: Your code here.
    if (tf->tf_trapno == T_PGFLT) {
        return page_fault_handler(tf);
    }   

    if (tf->tf_trapno == T_BRKPT) {
        return monitor(tf);
    }   

    // Unexpected trap: The user process or the kernel has a bug.
    print_trapframe(tf);
    if (tf->tf_cs == GD_KT)
        panic("unhandled trap in kernel");
    else {
        env_destroy(curenv);
        return;
    }   
}
```

### Question 3 & 4
为支持breakpoint，需要在初始化SETGATE做什么？
设置DPL为3，这些机制目的都是为了加强权限控制。

# Exercize 7 & 8
实现系统调用的支持，需要修改`trap_dispatch()`和`kern/syscall.c`。

在trap_dispatch()中加入如下代码

```
 if (tf->tf_trapno == T_SYSCALL) {
        tf->tf_regs.reg_eax = syscall(
            tf->tf_regs.reg_eax,
            tf->tf_regs.reg_edx,
            tf->tf_regs.reg_ecx,
            tf->tf_regs.reg_ebx,
            tf->tf_regs.reg_edi,
            tf->tf_regs.reg_esi
        );  
        return;
 }   
```

接着在`kern/syscall.c`中对不同类型的系统调用处理。

```
// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5) 
{
    switch (syscallno) {
    case SYS_cputs:
        sys_cputs((char *)a1, a2);
        return 0;
    case SYS_cgetc:
        return sys_cgetc();
    case SYS_getenvid:
        return sys_getenvid();
    case SYS_env_destroy:
        return sys_env_destroy(a1);
    default:
        return -E_INVAL;
    }
}
```
完成作业7之后，在执行`user/hello.c`的第二句cprintf报 page fault，因为还没有设置它用到的thisenv的值。在`lib/libmain.c`的libmain()如下设置即可完成作业8：

```
thisenv = &envs[ENVX(sys_getenvid())];
```
完成作业8后，我们可以看到`user_hello`的正确输出了：

```
...
Incoming TRAP frame at 0xefffffbc
hello, world
Incoming TRAP frame at 0xefffffbc
i am environment 00001000
Incoming TRAP frame at 0xefffffbc
[00001000] exiting gracefully
[00001000] free env 00001000
Destroyed the only environment - nothing more to do!
Welcome to the JOS kernel monitor!
Type 'help' for a list of commands.
K> 
```

# Exercize 9-10
处理在内核模式下出现page fault的情况，这里比较简单处理，直接panic。

```
void
page_fault_handler(struct Trapframe *tf)
{
    ...
    // Handle kernel-mode page faults.

    // LAB 3: Your code here.
    if ((tf->tf_cs & 3) == 0) {
        panic("kernel page fault at:%x\n", fault_va);
    }   
    ...
}
```

接下来实现`user_mem_check`防止内存访问超出范围。

```
int
user_mem_check(struct Env *env, const void *va, size_t len, int perm)
{
    uint32_t begin = (uint32_t)ROUNDDOWN(va, PGSIZE), end = (uint32_t)ROUNDUP(va + len, PGSIZE);
    int check_perm = (perm | PTE_P);
    uint32_t check_va = (uint32_t)va;

    for (; begin < end; begin += PGSIZE) {
        pte_t *pte = pgdir_walk(env->env_pgdir, (void *)begin, 0);
        if ((begin >= ULIM) || !pte || (*pte & check_perm) != check_perm) {
            user_mem_check_addr = (begin >= check_va ? begin : check_va);
            return -E_FAULT;
        }    
    }    

    return 0;
}
```

然后在 `kern/syscall.c`的 sys_cputs()中加入检查。

```
user_mem_assert(curenv, s, len, 0);
```

此外，在`kern/kdebug.c`的debuginfo_eip()中加入检查。

```
// Make sure this memory is valid.
// Return -1 if it is not.  Hint: Call user_mem_check.
// LAB 3: Your code here.
if (user_mem_check(curenv, usd, sizeof(struct UserStabData), PTE_U))
    return -1; 
            
// Make sure the STABS and string table memory is valid.
// LAB 3: Your code here.
if (user_mem_check(curenv, stabs, stab_end - stabs, PTE_U))
    return -1;

if (user_mem_check(curenv, stabstr, stabstr_end - stabstr, PTE_U))
    return -1;
```
这样，就完成了作业9-10。

至此，lab 3完成，`make grade`可以看到分数为`80/80`。

# 总结
### 进程如何继续运行？
进程从中断之后是如何保证继续运行的，这个是在`trap()`函数中实现的，在其中拷贝了内核栈上的Trapframe结构体的值到curenv的env_tf中，从而实现了进程运行状态保存。

```
void 
trap(struct Trapframe *tf) {
    ......
    if ((tf->tf_cs & 3) == 3) {
        // Trapped from user mode.
        assert(curenv);

        // Copy trap frame (which is currently on the stack)
        // into 'curenv->env_tf', so that running the environment
        // will restart at the trap point.
        curenv->env_tf = *tf;
        // The trapframe on the stack should be ignored from here on.
        tf = &curenv->env_tf;
    }  
    ......
} 
```
### 用户程序运行时寄存器切换
最后，我们再来验证下前面提到的异常/中断处理。先看下用户程序运行，我们知道用户程序是在env_pop_tf()后开始运行的，观察`user_hello`运行前后的寄存器的值。可以看到 CS,ES,DS,SS,ESP等寄存器的值都切换到了用户模式的值。

```
(gdb) b env_pop_tf
Breakpoint 1 at 0xf0103969: file kern/env.c, line 464.

(gdb) info registers
eax            0xf01c0000	-266600448
ecx            0x3d4	980
edx            0x3d5	981
ebx            0x10094	65684
esp            0xf0119fbc	0xf0119fbc
ebp            0xf0119fd8	0xf0119fd8
esi            0x10094	65684
edi            0x0	0
eip            0xf0103969	0xf0103969 <env_pop_tf>
eflags         0x86	[ PF SF ]
cs             0x8	8
ss             0x10	16
ds             0x10	16
es             0x10	16
fs             0x23	35
gs             0x23	35
...
(gdb) si
=> 0xf0103978 <env_pop_tf+15>:	iret   
0xf0103978	465		asm volatile(
(gdb) si
=> 0x800020:	cmp    $0xeebfe000,%esp   # 进入用户程序了
0x00800020 in ?? ()
(gdb) info registers
eax            0x0	0
ecx            0x0	0
edx            0x0	0
ebx            0x0	0
esp            0xeebfe000	0xeebfe000 # USTACKTOP为0xeebfe000
ebp            0x0	0x0
esi            0x0	0
edi            0x0	0
eip            0x800026	0x800026
eflags         0x46	[ PF ZF ]
cs             0x1b	27
ss             0x23	35
ds             0x23	35
es             0x23	35
fs             0x23	35
gs             0x23	35
```

### 系统调用堆栈切换和堆栈内容
接着我们继续运行，此时用户程序会触发系统调用，我们在handler48打个断点，观察下中断后的状态。此时可以看到 esp寄存器的值为 0xefffffec，这是怎么来的呢？我们知道内核栈的顶部KSTACKTOP为 0xf0000000，发生异常/中断时，CPU会压入旧的  SS, ESP, EFLAGS, CS, EIP的值到栈中，这样占用了20字节(0x14），这样正好esp为`0xf0000000-0x14=0xefffffec`。查看堆栈内容，存储的确实是用户程序的EIP，CS, EFLAGS, ESP 以及SS的值。

```
(gdb) b handler48
Breakpoint 2 at 0xf0104220: file kern/trapentry.S, line 65.
(gdb) c
Continuing.
=> 0xf0104220 <handler48>:	push   $0x0

Breakpoint 2, handler48 () at kern/trapentry.S:65
65	TRAPHANDLER_NOEC(handler48, T_SYSCALL)
(gdb) info registers
eax            0x2	2
ecx            0x0	0
edx            0x0	0
ebx            0x0	0
esp            0xefffffec	0xefffffec
ebp            0xeebfdfd0	0xeebfdfd0
esi            0x0	0
edi            0x0	0
eip            0xf0104220	0xf0104220 <handler48>
eflags         0x86	[ PF SF ]
cs             0x8	8
ss             0x10	16
ds             0x23	35
es             0x23	35
fs             0x23	35
gs             0x23	35

(gdb) x /5x 0xefffffec
0xefffffec:	0x00800b7f	0x0000001b	0x00000086	0xeebfdfc4
0xeffffffc:	0x00000023
```

接着我们继续单步运行，观察调用`trap()`之前的内核栈的内容，如下，可以看到其中的内容正好是Trapframe的结构，即第一个4字节存储的是之前esp的值，也就是Trapframe的起始位置。后面分别是8个通用寄存器的值，然后是ds, es寄存器的值0x23，接着是trapno 0x30(系统调用中断号)，因为没有错误码，接着是0，然后是用户程序 EIP, CS, EFLAGS, ESP, SS的值，确实如我们分析一样，至此lab 3的作业完成。

```
(gdb) info registers
eax            0x10	16
ecx            0x0	0
edx            0x0	0
ebx            0x0	0
esp            0xefffffb8	0xefffffb8
ebp            0xeebfdfd0	0xeebfdfd0
esi            0x0	0
edi            0x0	0
eip            0xf0104232	0xf0104232 <_alltraps+12>
eflags         0x86	[ PF SF ]
cs             0x8	8
ss             0x10	16
ds             0x10	16
es             0x10	16
fs             0x23	35
gs             0x23	35

(gdb) si
=> 0xf0104232 <_alltraps+12>:	call   0xf010406d <trap>
_alltraps () at kern/trapentry.S:79
79		call trap /*never return*/

(gdb) x /18x 0xefffffb8
0xefffffb8:	0xefffffbc	0x00000000	0x00000000	0xeebfdfd0
0xefffffc8:	0xefffffdc	0x00000000	0x00000000	0x00000000
0xefffffd8:	0x00000002	0x00000023	0x00000023	0x00000030
0xefffffe8:	0x00000000	0x00800b7f	0x0000001b	0x00000086
0xeffffff8:	0xeebfdfc4	0x00000023
```
