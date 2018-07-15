# Part A
## Exercize 1
完成mmio_map_region函数，用到boot_map_region，注意对begin和end分别向下向上取整。另外设置的page的权限是 `PTE_PCD|PTE_PWT|PTE_W`，权限不要搞错了。

```
void *
mmio_map_region(physaddr_t pa, size_t size)
{
    static uintptr_t base = MMIOBASE;
    size_t begin = ROUNDDOWN(pa, PGSIZE), end = ROUNDUP(pa + size, PGSIZE);
    size_t map_size = end - begin;
    if (base + map_size >= MMIOLIM) {
        panic("overflow MMIOLIM");
    }    
    boot_map_region(kern_pgdir, base, map_size, pa, PTE_PCD|PTE_PWT|PTE_W);
    uintptr_t result = base;
    base += map_size;
    return (void *)result;
}
```

## Exercize 2
阅读 boot_aps()、mpentry.S等代码，修改 `kern/pmap.c`中的`page_init()`将 MPENTRY_PADDR(0x7000)这一页不要加入到page_free_list。

```
void 
page_init(void){
	 ...
    size_t i, mp_page = PGNUM(MPENTRY_PADDR);
    for (i = 1; i < npages_basemem; i++) {
        if (i == mp_page) continue;
        ...
    }
    ...
}
```

完成1，2后，此时可以通过 `check_page_free_list()`检查，但是会在`check_kern_pgdir()`失败，继续。

## Question 1
为什么mpentry.S要用到MPBOOTPHYS，而boot.S不需要？
这是因为mpentry.S代码mpentry_start, mpentry_end的地址都在KERNBASE(0xf0000000）之上，实模式无法寻址，而我们将mpentry.S加载到了0x7000处，所以需要通过MPBOOTPHYS来寻址。而boot.S加载的位置本身就是实模式可寻址的低地址，所以不用额外转换。

## Exercize 3
修改 `mem_mp_init()`为每个cpu分配内核栈。注意，CPU内核栈之间有空出KSTKGAP(32KB)，其目的是为了避免一个CPU的内核栈覆盖另外一个CPU的内核栈，空出来这部分可以在栈溢出时报错。

```
static void
mem_init_mp(void)
{
	 int i;
    for (i = 0; i < NCPU; i++) {
        int kstacktop_i = KSTACKTOP - KSTKSIZE - i * (KSTKSIZE + KSTKGAP);
        boot_map_region(kern_pgdir, kstacktop_i, KSTKSIZE, PADDR(percpu_kstacks[i]), PTE_W);
    }

}
```

## Exercize 4
修改`trap_init_percpu()`，完成每个CPU的TSS初始化。设置ts_esp0和ts_ss0，注意，设置全局描述符的时候加上cpu_id作为索引值，ltr时要注意是加载的描述符的偏移值，所以记得`cpu_id<<3`。

```
void
trap_init_percpu(void)
{
    int cpu_id = thiscpu->cpu_id;
    struct Taskstate *this_ts = &thiscpu->cpu_ts;
    this_ts->ts_esp0 = KSTACKTOP - cpu_id * (KSTKSIZE + KSTKGAP);
    this_ts->ts_ss0 = GD_KD;
    this_ts->ts_iomb = sizeof(struct Taskstate);

    gdt[(GD_TSS0 >> 3) + cpu_id] = SEG16(STS_T32A, (uint32_t) (this_ts),
                    sizeof(struct Taskstate) - 1, 0); 
    gdt[(GD_TSS0 >> 3) + cpu_id].sd_s = 0;
    ltr(GD_TSS0 + (cpu_id << 3));
    lidt(&idt_pd);
}

```

## Exercize 5
加解内核锁，加锁有3个地方，释放锁在env_run里面。

```
// 加锁位置1 i386_init()的 boot_aps()函数前。
@@ -50,6 +50,7 @@ i386_init(void)
 
        // Acquire the big kernel lock before waking up APs
        // Your code here:
+       lock_kernel();
 
        // Starting non-boot CPUs
        boot_aps();

// 加锁位置2 mp_main()的函数末尾，这里还要加上 sched_yield()。
@@ -116,9 +120,11 @@ mp_main(void)
        // only one CPU can enter the scheduler at a time!
        //
        // Your code here:
+       lock_kernel();
+       sched_yield();
 
        // Remove this after you finish Exercise 6
-       for (;;);
+       // for (;;);

// 加锁位置3 trap()里面

+++ b/kern/trap.c
@@ -286,6 +286,7 @@ trap(struct Trapframe *tf)
                // Acquire the big kernel lock before doing any
                // serious kernel work.
                // LAB 4: Your code here.
+               lock_kernel();
                assert(curenv);
                
// 释放锁
@@ -535,6 +535,7 @@ env_run(struct Env *e)
        curenv->env_status = ENV_RUNNING;
        curenv->env_runs++;
        lcr3(PADDR(curenv->env_pgdir));
+       unlock_kernel();
        env_pop_tf(&curenv->env_tf);
 }
```

## Question 2
为什么有了大内核锁后还要给每个CPU分配一个内核栈？
这是因为虽然大内核锁限制了多个进程同时执行内核代码，但是在陷入trap()之前，CPU硬件已经自动压栈了SS, ESP, EFLAGS, CS, EIP等寄存器内容，而且在`trapentry.S`中也压入了错误码和中断号到内核栈中，所以不同CPU必须分开内核栈，否则多个CPU同时陷入内核时会破坏栈结构，此时都还没有进入到trap()的加大内核锁位置。

## Exercize 6
实现轮转调度。另外还要修改`kern/syscall.c`加入对 `SYS_yield` 的支持，并在`kern/init.c`中加载3个`user_yield`进程测试。

```
// kern/sched.c中调度函数实现
void
sched_yield(void)
{
	struct Env *idle;

	idle = curenv;
	int start_envid = idle ? ENVX(idle->env_id)+1 : 0;

	for (int i = 0; i < NENV; i++) {
		int j = (start_envid + i) % NENV;
		if (envs[j].env_status == ENV_RUNNABLE) {
			env_run(&envs[j]);
		}
	}

	if (idle && idle->env_status == ENV_RUNNING) {
		env_run(idle);
	}

	// sched_halt never returns
	sched_halt();
}

// kern/syscall.c修改
@@ -284,6 +284,9 @@ syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
                return sys_getenvid();
        case SYS_env_destroy:
                return sys_env_destroy(a1);
+       case SYS_yield:
+               sys_yield();
+               return 0;
        default:
                return -E_INVAL;
        }
   
// 修改测试进程     
@@ -59,7 +60,10 @@ i386_init(void)
        ENV_CREATE(TEST, ENV_TYPE_USER);
 #else
        // Touch all you want.
-       ENV_CREATE(user_primes, ENV_TYPE_USER);
+       // ENV_CREATE(user_primes, ENV_TYPE_USER);
+       ENV_CREATE(user_yield, ENV_TYPE_USER);
+       ENV_CREATE(user_yield, ENV_TYPE_USER);
+       ENV_CREATE(user_yield, ENV_TYPE_USER);
```


完成作业5，6后，应该可以看到下面的输出：

```
Hello, I am environment 00001000.
Hello, I am environment 00001001.
Back in environment 00001000, iteration 0.
Hello, I am environment 00001002.
Back in environment 00001000, iteration 1.
Back in environment 00001001, iteration 0.
Back in environment 00001002, iteration 0.
Back in environment 00001000, iteration 2.
Back in environment 00001002, iteration 1.
Back in environment 00001001, iteration 1.
Back in environment 00001000, iteration 3.
Back in environment 00001002, iteration 2.
Back in environment 00001001, iteration 2.
Back in environment 00001000, iteration 4.
```

## Question 3
在env_run中，我们在调用lcr3()切换页目录之前和之后都引用了变量e，为什么切换了页目录还是可以正确引用e呢？

这是因为所有的进程env_pgdir的高地址的映射跟kern_pgdir的是一样的，见实验3的env_setup_vm()。

## Question 4
为什么要保证我们的进程保存了寄存器状态，在哪里保存的？
当然要保存寄存器状态，以知道下一条指令地址以及进程栈的状态，不然我们不知道从哪里继续运行。保存寄存器状态的代码是 trap.c 中的 `curenv->env_tf = *tf;`

## Exercize 7
实现 sys_exofork，sys_env_set_status，sys_page_alloc，sys_page_map，sys_page_unmap 这几个系统调用，参照提示依次完成，别忘了在syscall()函数中加入对应的系统调用分发代码，最后修改 kern/init.c 中加载的用户程序为 `user_dumbfork`即可开始测试。

```
static envid_t
sys_exofork(void)
{
    struct Env *e; 
    int ret = env_alloc(&e, curenv->env_id);
    if (ret) return ret;

    e->env_status = ENV_NOT_RUNNABLE;
    e->env_tf = curenv->env_tf;
    e->env_tf.tf_regs.reg_eax = 0;
    return e->env_id;
}

static int
sys_env_set_status(envid_t envid, int status)
{
    struct Env *e;
    if (envid2env(envid, &e, 1)) return -E_BAD_ENV;
    
    if (status != ENV_NOT_RUNNABLE && status != ENV_RUNNABLE) return -E_INVAL;
    
    e->env_status = status;
    return 0;
}

static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
    struct Env *e;
    if (envid2env(envid, &e, 1) < 0) return -E_BAD_ENV;

    int valid_perm = (PTE_U|PTE_P);
    if (va >= (void *)UTOP || (perm & valid_perm) != valid_perm) {
        return -E_INVAL;
    }

    struct PageInfo *p = page_alloc(1);
    if (!p) return -E_NO_MEM;

    int ret = page_insert(e->env_pgdir, p, va, perm);
    if (ret) {
        page_free(p);
    }
    return ret;
}

static int
sys_page_map(envid_t srcenvid, void *srcva,
         envid_t dstenvid, void *dstva, int perm)
{
    struct Env *srcenv, *dstenv;
    if (envid2env(srcenvid, &srcenv, 1) || envid2env(dstenvid, &dstenv, 1)) {
        return -E_BAD_ENV;
    }

    if (srcva >= (void *)UTOP || dstva >= (void *)UTOP || PGOFF(srcva) || PGOFF(dstva)) {
        return -E_INVAL;
    }

    pte_t *pte;
    struct PageInfo *p = page_lookup(srcenv->env_pgdir, srcva, &pte);
    if (!p) return -E_INVAL;

    int valid_perm = (PTE_U|PTE_P);
    if ((perm&valid_perm) != valid_perm) return -E_INVAL;

    if ((perm & PTE_W) && !(*pte & PTE_W)) return -E_INVAL;

    int ret = page_insert(dstenv->env_pgdir, p, dstva, perm);
    return ret;
}

static int
sys_page_unmap(envid_t envid, void *va)
{
    struct Env *e;
    if (envid2env(envid, &e, 1)) return -E_BAD_ENV;

    if (va >= (void *)UTOP) return -E_INVAL;

    page_remove(e->env_pgdir, va);
    return 0;
}

int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	 ...
    case SYS_exofork:
        return sys_exofork();
    case SYS_env_set_status:
        return sys_env_set_status(a1, a2);
    case SYS_page_alloc:
        return sys_page_alloc(a1, (void *)a2, a3);
    case SYS_page_map:
        return sys_page_map(a1, (void*)a2, a3, (void*)a4, a5);
    case SYS_page_unmap:
        return sys_page_unmap(a1, (void *)a2);
    ...
}
```

完成后运行`./grade-lab4`，应该可以看到 Part A得分为5分。

# Part B
## Exercize 8
完成sys_env_set_pgfault_upcall，如下：

```
static int 
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
    struct Env *e; 
    if (envid2env(envid, &e, 1)) return -E_BAD_ENV;
    e->env_pgfault_upcall = func;
    return 0;
}
```

## Exercize 9
在page_fault_handler完成用户页面错误的处理，主要是切换堆栈到异常栈，并设置异常栈内容，最后设置EIP为页面错误处理函数的地址，切回用户态执行页面错误处理函数。注意嵌套页错误的处理，嵌套页错误时，需要保留4字节用于设置EIP。

```
void 
page_fault_handler(Trapframe *tf) {
    ...
    // LAB 4: Your code here.
    if (curenv->env_pgfault_upcall) {
        struct UTrapframe *utf;
        if (tf->tf_esp >= UXSTACKTOP-PGSIZE && tf->tf_esp <= UXSTACKTOP-1) {
            utf = (struct UTrapframe *)(tf->tf_esp - sizeof(struct UTrapframe) - 4); 
        } else {
            utf = (struct UTrapframe *)(UXSTACKTOP - sizeof(struct UTrapframe));
        }   

        user_mem_assert(curenv, (void*)utf, 1, PTE_W);
        utf->utf_fault_va = fault_va;
        utf->utf_err = tf->tf_err;
        utf->utf_regs = tf->tf_regs;
        utf->utf_eip = tf->tf_eip;
        utf->utf_eflags = tf->tf_eflags;
        utf->utf_esp = tf->tf_esp;

        curenv->env_tf.tf_eip = (uintptr_t)curenv->env_pgfault_upcall;
        curenv->env_tf.tf_esp = (uintptr_t)utf;
        env_run(curenv);
    } 
    ...
} 
```

## Exercize 10
完成_pgfault_upcall，这理论分析已经解析过这部分代码，如下：

```
_pgfault_upcall:
        ...
        // LAB 4: Your code here.
        movl 0x28(%esp), %ebx  # trap-time eip
        subl $0x4, 0x30(%esp)  # trap-time esp minus 4
        movl 0x30(%esp), %eax 
        movl %ebx, (%eax)      # trap-time esp store trap-time eip
        addl $0x8, %esp 

        // Restore the trap-time registers.  After you do this, you
        // can no longer modify any general-purpose registers.
        // LAB 4: Your code here.
        popal

        // Restore eflags from the stack.  After you do this, you can
        // no longer use arithmetic operations or anything else that
        // modifies eflags.
        // LAB 4: Your code here.
        addl $0x4, %esp
        popfl
    

        // Switch back to the adjusted trap-time stack.
        // LAB 4: Your code here.
        popl %esp

        // Return to re-execute the instruction that faulted.
        // LAB 4: Your code here.
        ret 
```

## Exercize 11
完成`lib/pgfault.c`中的 `set_pgfault_handler()`。

```
void
set_pgfault_handler(void (*handler)(struct UTrapframe *utf))
{
    int r;

    if (_pgfault_handler == 0) {
        // First time through!
        // LAB 4: Your code here.
        if (sys_page_alloc(0, (void *)(UXSTACKTOP - PGSIZE), PTE_W|PTE_U|PTE_P)) {
            panic("set_pgfault_handler page_alloc failed");
        }   
        if (sys_env_set_pgfault_upcall(0, _pgfault_upcall)) {
            panic("set_pgfault_handler set_pgfault_upcall failed");
        }   
    }   

    _pgfault_handler = handler;
}
```

完成作业11后，可以看到`user/faultread`，`user/faultalloc`,`user/faultallocbad`等可以正常通过测试了。这里要注意 faultalloc和faultallocbad为什么会表现不同？看代码可以知道 faultallocbad 是直接通过系统调用 sys_puts 输出字符串的，而在内核的sys_cputs中有对访问地址进行检查 `user_mem_assert(curenv, s, len, 0);`，因为访问了非法地址，所以直接报错了。而faultalloc是通过cprintf访问的，在调用 sys_cputs之前，会将要输出的字符串存储到 printbuf中，此时会访问地址 0xdeadbeef，从而导致页错误。

这里有意思的是访问 0xcafebffe 这个地址的内容会报两次页错误，因为第一次是 0xcafebffe 处没有映射，于是会分配 0xcafeb000到0xcafebfff的一页。而后面输出 `this string...` 时，因为snprintf访问到了 0xcafec000 后面的地址，导致再次发生页错误，所以会输出两行fault。

```
# make run-faultalloc
fault deadbeef
this string was faulted in at deadbeef
fault cafebffe
fault cafec000
this string was faulted in at cafebffe

# make run-faultallocbad
[00001000] user_mem_check assertion failure for va deadbeef
```

## Exercize 12

完成fork()，duppage()以及pgfault()。**注意我这里在fork中拷贝的页面是以程序end作为结束的，这在lab5文件系统的实验中会有些坑，不过不影响lab4的测试，详见lab5的修改。**

```
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// LAB 4: Your code here.
	if (!((err & FEC_WR) && (uvpd[PDX(addr)] & PTE_P)
			&& (uvpt[PGNUM(addr)] & PTE_COW) && (uvpt[PGNUM(addr)] & PTE_P)))
		panic("page cow check failed");

	addr = ROUNDDOWN(addr, PGSIZE);

	// LAB 4: Your code here.
	if ((r = sys_page_alloc(0, PFTEMP, PTE_P|PTE_U|PTE_W)))
		panic("sys_page_alloc: %e", r);

	memmove(PFTEMP, addr, PGSIZE);

	if ((r = sys_page_map(0, PFTEMP, 0, addr, PTE_P|PTE_U|PTE_W)))
		panic("sys_page_map: %e", r);

	if ((r = sys_page_unmap(0, PFTEMP)))
		panic("sys_page_unmap: %e", r);

}

static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	void *addr = (void *)(pn * PGSIZE);
	if (uvpt[pn] & (PTE_W|PTE_COW)) {
		if ((r = sys_page_map(0, addr, envid, addr, PTE_COW|PTE_U|PTE_P)) < 0)
			panic("sys_page_map COW:%e", r);

		if ((r = sys_page_map(0, addr, 0, addr, PTE_COW|PTE_U|PTE_P)) < 0)
			panic("sys_page_map COW:%e", r);
	} else {
		if ((r = sys_page_map(0, addr, envid, addr, PTE_U|PTE_P)) < 0)
			panic("sys_page_map UP:%e", r);
	}
	return 0;
}

envid_t
fork(void)
{
	// LAB 4: Your code here.
	// panic("fork not implemented");
	set_pgfault_handler(pgfault);

	envid_t envid = sys_exofork();
	uint8_t *addr;
	if (envid < 0)
		panic("sys_exofork:%e", envid);
	if (envid == 0) {
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	extern unsigned char end[];
	for (addr = (uint8_t *)UTEXT; addr < end; addr += PGSIZE) {
		if ((uvpd[PDX(addr)] & PTE_P) && (uvpt[PGNUM(addr)] & PTE_P)
				&& (uvpt[PGNUM(addr)] & PTE_U)) {
			duppage(envid, PGNUM(addr));
		}
	}

	duppage(envid, PGNUM(ROUNDDOWN(&addr, PGSIZE)));

	int r;
	if ((r = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), PTE_P|PTE_U|PTE_W)))
		panic("sys_page_alloc:%e", r);

	extern void _pgfault_upcall();
	sys_env_set_pgfault_upcall(envid, _pgfault_upcall);

	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)))
		panic("sys_env_set_status:%e", r);

	return envid;
}
```

# Part C
## Exercize 13-14
添加中断处理函数，跟之前设置异常和中断差不多，注意此时所有的istrap要全部设置为0，否则会通不过 FL_IF的检查。

```
//trapentry.S
...
TRAPHANDLER_NOEC(handler32, IRQ_OFFSET + IRQ_TIMER)
TRAPHANDLER_NOEC(handler33, IRQ_OFFSET + IRQ_KBD)
TRAPHANDLER_NOEC(handler36, IRQ_OFFSET + IRQ_SERIAL)
TRAPHANDLER_NOEC(handler39, IRQ_OFFSET + IRQ_SPURIOUS)
TRAPHANDLER_NOEC(handler46, IRQ_OFFSET + IRQ_IDE)
TRAPHANDLER_NOEC(handler51, IRQ_OFFSET + IRQ_ERROR)

//trap.c的trap_init()
SETGATE(idt[IRQ_OFFSET+IRQ_TIMER], 0, GD_KT, handler32, 0);
SETGATE(idt[IRQ_OFFSET+IRQ_KBD], 0, GD_KT, handler33, 0);
SETGATE(idt[IRQ_OFFSET+IRQ_SERIAL], 0, GD_KT, handler36, 0);
SETGATE(idt[IRQ_OFFSET+IRQ_SPURIOUS], 0, GD_KT, handler39, 0);
SETGATE(idt[IRQ_OFFSET+IRQ_IDE], 0, GD_KT, handler46, 0);
SETGATE(idt[IRQ_OFFSET+IRQ_ERROR], 0, GD_KT, handler51, 0);

// trap.c的trap_dispatch()
// Handle clock interrupts. Don't forget to acknowledge the
// interrupt using lapic_eoi() before calling the scheduler!
// LAB 4: Your code here.
if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
       lapic_eoi();
       sched_yield();
       return;
}
```

## Exercize 15
完成IPC功能，别忘记在syscall里面分发加新增的两个系统调用。

```
int32_t
ipc_recv(envid_t *from_env_store, void *pg, int *perm_store)
{
    if (pg == NULL) pg = (void *)UTOP;

    int r = sys_ipc_recv(pg);
    int from_env = 0, perm = 0;
    if (r == 0) {
        from_env = thisenv->env_ipc_from;
        perm = thisenv->env_ipc_perm;
        r = thisenv->env_ipc_value;
    } else {
        from_env = 0;
        perm = 0;
    }   

    if (from_env_store) *from_env_store = from_env;
    if (perm_store) *perm_store = perm;

    return r;
}

void
ipc_send(envid_t to_env, uint32_t val, void *pg, int perm)
{
    if (pg == NULL) pg = (void *)UTOP;

    int ret;
    while ((ret = sys_ipc_try_send(to_env, val, pg, perm))) {
        if (ret != -E_IPC_NOT_RECV) panic("ipc_send error %e", ret);
        sys_yield();
    }
}

static int 
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
    struct Env *e; 
    if (envid2env(envid, &e, 0)) return -E_BAD_ENV;

    if (!e->env_ipc_recving) return -E_IPC_NOT_RECV;

    if (srcva < (void *) UTOP) {
        if(PGOFF(srcva)) return -E_INVAL;

        pte_t *pte;
        struct PageInfo *p = page_lookup(curenv->env_pgdir, srcva, &pte);
        if (!p) return -E_INVAL;

        if ((*pte & perm) != perm) return -E_INVAL;

        if ((perm & PTE_W) && !(*pte & PTE_W)) return -E_INVAL;

        if (e->env_ipc_dstva < (void *)UTOP) {
            int ret = page_insert(e->env_pgdir, p, e->env_ipc_dstva, perm);
            if (ret) return ret;
            e->env_ipc_perm = perm;
        }   
    }   

    e->env_ipc_recving = 0;
    e->env_ipc_from = curenv->env_id;
    e->env_ipc_value = value;
    e->env_status = ENV_RUNNABLE;
    e->env_tf.tf_regs.reg_eax = 0;
    return 0;
}


static int 
sys_ipc_recv(void *dstva)
{
    if ((dstva < (void *)UTOP) && PGOFF(dstva))
        return -E_INVAL;

    curenv->env_ipc_recving = 1;
    curenv->env_status = ENV_NOT_RUNNABLE;
    curenv->env_ipc_dstva = dstva;
    sys_yield();
    return 0;
}

int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5) 
{
    case SYS_ipc_try_send:
        return sys_ipc_try_send(a1, a2, (void *)a3, a4);
    case SYS_ipc_recv:
        return sys_ipc_recv((void *)a1);
    ...
}
```
