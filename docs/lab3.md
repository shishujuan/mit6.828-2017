# 1 概述

即内存管理之后，实验3是实现用户环境，这里的用户环境，其实就类比Unix/Linux下的进程即可。因为JOS的环境与Unix进程提供了不同的接口和语义，所以用环境一词代替进程，在本文中进程和环境两个词就不做区分了。

# 2 进程定义
在 `inc/env.h`中包含了一些用户环境的基本定义，JOS内核使用 `Env`结构体来追踪用户进程。其中 envs变量是指向所有进程的链表的指针，其操作方式跟实验2的pages类似，env_free_list是空闲的进程结构链表。注意下，在早起的JOS实验中，pages和envs都是用的双向链表，现在的版本用的单向链表操作起来更加简单和清晰。

```
struct Env *envs = NULL;		// All environments
struct Env *curenv = NULL;		// The current env
static struct Env *env_free_list;	// Free environment list
```

注意，现代操作系统中通常都可以多进程并发执行的，这取决于 PCB 表的大小。在 JOS 系 统中，evns 数组就等价于 PCB 表，其共有 1024(NENV)个表项，即 JOS 系统并发度为 1024。 其相关宏在 inc/Env.h 中定义:

```
// +1+---------------21-----------------+--------10--------+
// |0|          Uniqueifier             |   Environment    |
// | |                                  |      Index       |
// +------------------------------------+------------------+
//                                       \--- ENVX(eid) --/
#define LOG2NENV		10
#define NENV			(1 << LOG2NENV)
#define ENVX(envid)		((envid) & (NENV - 1))

struct Env {
	struct Trapframe env_tf;	// Saved registers
	struct Env *env_link;		// Next free Env
	envid_t env_id;			// Unique environment identifier
	envid_t env_parent_id;		// env_id of this env's parent
	enum EnvType env_type;		// Indicates special system environments
	unsigned env_status;		// Status of the environment
	uint32_t env_runs;		// Number of times environment has run

	// Address space
	pde_t *env_pgdir;		// Kernel virtual address of page dir
};
```

进程结构体 Env 各字段定义如下：

- env_tf： 当进程停止运行时用于保存寄存器的值，比如当发生中断切换到内核环境运行了或者切换到另一个进程运行的时候需要保存当前进程的寄存器的值以便后续该进程继续执行。
- env_link：指向空闲进程链表 env_free_list 中的下一个 Env 结构。
- env_id： 进程ID。因为进程ID是正数，所以符号位是0，而中间的21位是标识符，标识在不同的时间创建但是却共享同一个进程索引号的进程，最后10位是进程的索引号，要用envs索引进程管理结构 Env 就要用 `ENVX(env_id)`。
- env_parent_id： 进程的父进程ID。
- env_type：进程类型，通常是 ENV_TYPE_USER，后面实验中可能会用到其他类型。
- env_status：进程状态，进程可能处于下面几种状态
	- ENV_FREE：标识该进程结构处于不活跃状态，存在于 env_free_list 链表。
	- ENV_RUNNABLE: 标识该进程处于等待运行的状态。
	- ENV_RUNNING: 标识该进程是当前正在运行的进程。
	- ENV_NOT_RUNNABLE: 标识该进程是当前运行的进程，但是处于不活跃的状态，比如在等待另一个进程的IPC。
	- ENV_DYING: 该状态用于标识僵尸进程。在实验4才会用到这个状态，实验3不用。
- env_pgdir：用于保存进程页目录的**虚拟地址**。



# 3 进程初始化及运行

进程管理结构envs对应的1024个Env结构体在物理内存中紧接着pages存储。进程初始化流程主要包括：

- 给NENV个Env结构体在内存中分配空间，并将 envs 结构体的物理地址映射到 从 UENV 所指向的线性地址空间，该线性地址空间允许用户访问且只读，所以页面权限被标记为PTE_U。
- 调用`env_init`函数初始化envs，将 NENV 个进程管理结构Env通过env_link串联起来，注意，env_free_list要指向第一个 Env，所以这里要用倒序的方式。在`env_init`函数中调用了`env_init_percpu`函数，加载新的全局描述符表，设置内核用到的寄存器 es, ds, ss的值为GD_KD，即内核的段选择子，DPL为0。然后通过ljmp指令`asm volatile("ljmp %0,$1f\n 1:\n" : : "i" (GD_KT));`设置CS为 GD_KT。这句汇编用到了`unnamed local labels`，含义就是跳转到 `GD_KT, 1:`这个地址处，其中的 `$1f`的意思是指跳转到后一个`1:`标签处，如果是前一个，用`$1b`，而这个后一个`1:`标签就是语句后面，所以最终效果只是设置了CS寄存器的值为GD_KT而已。
- 初始化好了envs和env_free_list后，接着调用 `ENV_CREATE(user_hello, ENV_TYPE_USER)` 创建用户进程。`ENV_CREATE`是`kern/env.h`中的宏定义，展开就是调用的 `env_create`,只是参数设置成了 `env_create(_binary_obj_user_hello_start, ENV_TYPE_USER)`。env_create也是我们要实现的函数，它的功能就是先调用`env_alloc`函数分配好Env结构，初始化Env的各个字段值(如env_id，env_type，env_status以及env_tf的用于存储寄存器值的字段，运行用户程序时会将 env_tf 的字段值加载到对应的寄存器中)，为该用户进程分配页目录表并调用`load_icode`函数加载程序代码到内存中。
	- env_alloc调用env_setup_vm函数分配好页目录的页表，并设置页目录项和env_pgdir字段)。
	- `load_icode`函数则是**先设置cr3寄存器切换到该进程的页目录env_pgdir**，然后通过`region_alloc`分配每个程序段的内存并按segment将代码加载到对应内存中，加载完成后设置 env_tf->tf_eip为Elf的e_entry，即程序的初始执行位置。
- 加载完程序代码后，万事俱备，调用 `env_run(e)` 函数开始运行程序。如果当前有进程正在运行，则设置当前进程状态为`ENV_RUNNABLE`，并将需要运行的进程e的状态设置为`ENV_RUNNING`，**然后加载e的页目录表地址 env_pgdir 到cr3寄存器中**，调用 `env_pop_tf(struct Trapframe *tf)` 开始执行程序e。
- env_pop_tf其实就是将栈指针esp指向该进程的env_tf，然后将 env_tf 中存储的寄存器的值弹出到对应寄存器中，最后通过 iret 指令弹出栈中的元素分别到 EIP, CS, EFLAGS 到对应寄存器并跳转到 `CS:EIP` 存储的地址执行(当使用iret指令返回到一个不同特权级运行时，还会弹出堆栈段选择子及堆栈指针分别到SS与SP寄存器)，这样，相关寄存器都从内核设置成了用户程序对应的值，EIP存储的是程序入口地址。
- env_id的生成规则很有意思，注意一下在env_free中并没有重置env_id的值，这就是为了用来下一次使用这个env结构体时生成一个新的env_id，区分之前用过的env_id，从generation的生成方式就能明白了。

用户程序运行路径如下所示：

```
start (kern/entry.S)
i386_init (kern/init.c)
	cons_init
	mem_init
	env_init
	trap_init (still incomplete at this point)
	env_create
		env_alloc
			env_setup_vm
		load_icode
			region_alloc
	env_run
		env_pop_tf
```

### 关于Trapframe
Trapframe结构体存储的是当前进程的寄存器的值，可以看到`env_pop_tf`函数中便是将trapframe的起始地址赋值给esp，然后用的这个顺序将栈中元素弹出到对应寄存器中的。其中popal是弹出tf_regs到所有的通用寄存器中，接着弹出值到es，ds寄存器，接着跳过trapno和errcode，调用iret分别将栈中存储数据弹出到 EIP, CS, EFLAGS寄存器中。

```
struct Trapframe {
    struct PushRegs tf_regs;
    uint16_t tf_es;
    uint16_t tf_padding1;
    uint16_t tf_ds;
    uint16_t tf_padding2;
    uint32_t tf_trapno;
    /* below here defined by x86 hardware */
    uint32_t tf_err;
    uintptr_t tf_eip;
    uint16_t tf_cs;
    uint16_t tf_padding3;
    uint32_t tf_eflags;
    /* below here only when crossing rings, such as from user to kernel */
    uintptr_t tf_esp;
    uint16_t tf_ss;
    uint16_t tf_padding4;
} __attribute__((packed));

//
// Restores the register values in the Trapframe with the 'iret' instruction.
// This exits the kernel and starts executing some environment's code.
//
// This function does not return.
//
void env_pop_tf(struct Trapframe *tf)
{
    asm volatile(
        "\tmovl %0,%%esp\n"
        "\tpopal\n"
        "\tpopl %%es\n"
        "\tpopl %%ds\n"
        "\taddl $0x8,%%esp\n" /* skip tf_trapno and tf_errcode */
        "\tiret\n"
        : : "g" (tf) : "memory");
    panic("iret failed");  /* mostly to placate the compiler */
}
```


### 关于CPL, RPL, DPL
CPL是当前正在执行的代码所在的段的特权级，存在于CS寄存器的低两位(对CS来说，选择子的RPL=当前段的CPL)。RPL指的是进程对段访问的请求权限，是针对段选择子而言的，不是固定的。DPL则是在段描述符中存储的，规定了段的访问级别，是固定的。为什么需要RPL呢？因为同一时刻只能有一个CPL，而低权限的用户程序去调用内核的功能来访问一个目标段时，进入内核代码段时CPL 变成了内核的CPL，如果没有RPL，那么权限检查的时候就会用CPL，而这个CPL 权限比用户程序权限高，也就可能去访问需要高权限才能访问的数据，导致安全问题。所以引入RPL，让它去代表访问权限，因此在检查CPL 的同时，也会检查RPL。一般来说如果RPL 的数字比CPL大(权限比CPL的低)，那么RPL会起决定性作用，这个权限检查是CPU硬件层面做的。

### 用户程序代码
实验中用到的用户程序代码位于user目录，如user_hello对应的源文件是`user/hello.c`，**因为还没有实现文件系统，所以这些用户程序代码通过一系列编译命令后最终会编译到内核中**。比如 `user/hello.c` 编译到内核中地址是 `0xf011c356`。详见 `kern/Makefrag`，用命令`make V=1`可以显示完整的编译命令。

之前有个疑惑就是 `user/hello.c` 是怎么编译到kernel里面后在`obj/kern/kernel.sym`有了 `_binary_obj_user_hello_start`、`_binary_obj_user_hello_end`以及`_binary_obj_user_hello_size`这几个符号的。这个其实是 `ld`命令生成的。具体命令是下面这个，`ld -b binary`会自动在最终的可kernel文件中生成对应开始结束符号，以`_binary_`开头，因为我们的用户程序编译后代码目录结构是 `obj/user/hello`，所以符号名就是将目录换成了下划线。

```
ld -o obj/kern/kernel -m elf_i386 -T kern/kernel.ld -nostdlib obj/kern/entry.o obj/kern/entrypgdir.o ... /usr/lib/gcc/x86_64-linux-gnu/4.8/32/libgcc.a 
    -b binary  obj/user/hello ...
```
另外提下的是，kern.sym 这个符号表文件里面存储的是符号的地址。符号有类型，大写表示全局符号，小写则是局部符号。类型说明：

- A：符号是绝对值。比如表示代码长度的符号 `_binary_obj_user_hello_size`。
- T: 代码段符号。
- D：已初始化数据段符号。
- B：未初始化数据段符号。

### 用户代码中的系统调用
在 Env初始化后，运行编译好的 `user_hello` 进程会报错，因为 `user_hello`里面调用了 `cprintf` 打印输出，我们不能让用户程序来操作硬件设备，因此cprintf最终要通过系统调用来实现，此时系统调用功能还没有实现。

**注意 `kern` 和 `lib`目录下面都有 `printf.c和syscall.c`文件**，kern目录下面的是内核专用的。而用户要cprintf输出，就要使用lib目录下面的printf.c中的函数，最后经由`lib/syscall.c`的`sys_cputs()`，最终通过该文件中的`syscall()`来实现输出。


# 4 中断和异常处理
## 4.1 中断/异常概述
中断和异常都是”保护控制转移(PCT)”机制，它们将处理器从用户模式转换到内核模式。在英特尔的术语中，中断是指处理器之外的异步事件导致的PCT，比如外部的IO设备活动。而异常则是当前运行代码同步触发的PCT，如除0或者非法内存访问等。根据异常被报告的方式以及导致异常的指令是否能重新执行，异常还可以细分为故障（Fault），陷阱（Trap）和中止（Abort）。JOS中断在门描述符中的type为STS_IG32，异常的type为 STS_TG32。

* Fault是通常可以被纠正的异常，纠正后可以继续运行。出现Fault时，处理器会把机器状态恢复到产生Fault指令之前的状态，此时异常处理程序返回地址会指向产生Fault的指令，而不是后一条指令，产生Fault的指令在中断处理程序返回后会重新执行。如Page Fault。
* Trap处理程序返回后执行的指令是引起陷阱指令的后一条指令。
* Abort则不允许异常指令继续执行。

中断描述符表将每个中断向量和一个中断门描述符对应起来，中断门描述符里面存储中断或异常的处理程序的入口地址以及DPL。x86 允许256个中断和异常入口，每个对应一个唯一的整数值，称为中断向量。中断描述符表的起始地址存储在IDT寄存器中，当发生中断/异常时，CPU使用中断向量作为中断描述符表的索引，通过中断门描述符中存储的段选择子和偏移量，可以到GDT中找到中断处理程序的地址。


```
       IDT                   trapentry.S         trap.c
   
+----------------+                        
|   &handler1    |---------> handler1:          trap (struct Trapframe *tf)
|                |             // do stuff      {
|                |             call trap          // handle the exception/interrupt
|                |             // ...           }
+----------------+
|   &handler2    |--------> handler2:
|                |            // do stuff
|                |            call trap
|                |            // ...
+----------------+
       .
       .
       .
+----------------+
|   &handlerX    |--------> handlerX:
|                |             // do stuff
|                |             call trap
|                |             // ...
+----------------+
```

x86 使用0-31号中断向量作为处理器内部的同步的异常类型，比如除零和缺页异常。而32号之上的中断向量用于软件中断(如int指令产生的软件中断)或者外部设备产生的异步的硬件中断。lab 3我们会用到0-31号以及48号(用于系统调用)中断向量，在后面实验中还会处理外部的时钟中断，JOS 用到的中断如下：

```
#define T_DIVIDE     0      // divide error
#define T_DEBUG      1      // debug exception
#define T_NMI        2      // non-maskable interrupt
#define T_BRKPT      3      // breakpoint
#define T_OFLOW      4      // overflow
#define T_BOUND      5      // bounds check
#define T_ILLOP      6      // illegal opcode
#define T_DEVICE     7      // device not available
#define T_DBLFLT     8      // double fault
/* #define T_COPROC  9 */   // reserved (not generated by recent processors)
#define T_TSS       10      // invalid task switch segment
#define T_SEGNP     11      // segment not present
#define T_STACK     12      // stack exception
#define T_GPFLT     13      // general protection fault
#define T_PGFLT     14      // page fault
/* #define T_RES    15 */   // reserved
#define T_FPERR     16      // floating point error
#define T_ALIGN     17      // aligment check
#define T_MCHK      18      // machine check
#define T_SIMDERR   19      // SIMD floating point error

// These are arbitrarily chosen, but with care not to overlap
// processor defined exceptions or interrupt vectors.
#define T_SYSCALL   48      // system call
```

## 4.2 中断/异常处理流程
在用户程序内发生中断/异常时，CPU会自动将控制器转移到中断处理程序处。前面提到，中断门描述符存储了中断处理程序的信息，包括其所在的段选择子、代码地址等。CPU通过IDT寄存器找到中断描述符表的起始地址，然后通过中断向量(即中断号)找到对应的中断门描述符，接着通过中断门描述符中存储的段选择子到GDT中找到段基址，加上偏移地址即可得到中断处理程序的地址。具体流程如下图所示：

![中断处理流程](https://upload-images.jianshu.io/upload_images/286774-75b21c6af3077c6c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


在跳转到中断处理程序执行之前，处理器需要一个地方保存处理器出现中断/异常前的状态，如调用异常处理程序之前的EIP 和 CS的值，这样处理完中断/异常后可以从出现中断/异常前的位置继续执行。需要注意的是，这块区域不能被用户模式的代码访问到。基于这个考虑，当x86遇到异常/中断导致特权级从用户模式转移到内核模式时，它会将堆栈切换到内核栈。TSS就是存储这个堆栈位置的结构，包括堆栈的段选择子和地址等。发生特权级别切换时，切换到内核栈后，处理器会在内核栈中压入 SS, ESP, EFLAGS, CS, EIP。然后它从中断门描述符将对应的值到加载到寄存器器CS, EIP中，并将 ESP和SS设置为指向新的堆栈。尽管TSS有很多字段，但是在JOS中只用到了ESP0和SS0来存储内核栈的地址，其他字段都没有使用。其中TSS的段选择子通过`ltr`指令加载到TR寄存器中，TR寄存器是个段寄存器，内容为段选择子的值，注意段寄存器存的是段选择子在全局描述符的偏移值，并不是索引值。

```
ts.ts_esp0 = KSTACKTOP;
ts.ts_ss0 = GD_KD;
```

中断门描述符在 `trap_init()`中初始化，通过 `SETGATE`定义。大部分的中断门描述符的DPL为0，少量的需要允许用户模式调用的设置为3，如系统调用SYSCALL和断点BRKPT.

```
 SETGATE(idt[T_DIVIDE], 0, GD_KT, &handler1, 0);
 ...
 SETGATE(idt[T_SYSCALL], 0, GD_KT, &handler48, 3);
```

注意，异常/中断处理时切换堆栈到内核栈是处理器执行的，在内核栈压入SS, ESP, EFLAGS, CS, EIP等寄存器的值也是处理器做的。我们要做的是将TSS的ESP0和SS0设置为内核栈地址，然后将错误码和异常代号trapno压入内核栈，接着将ds，es，通用寄存器等寄存器的值压入内核栈中，切换ds和es寄存器的值到内核数据段GD_KD(_alltraps中处理)，这样栈中的数据满足了Trapframe结构，后面调用trap()函数统一处理。trap()函数最终通过`trap_dispatch()`函数根据中断向量来分发中断/异常处理，在lab 3中我们只处理了 T_PGFLT，T_BRKPT，T_SYSCALL 这三个中断向量，其他的则直接销毁env并进入monitor()。


## 4.3 中断/异常示例

用户模式下发生除零中断时，处理器会先切换到 TSS 中存储的esp0和ss0对应的内核栈，并在内核栈压入必要的信息，如下所示：

```
     +--------------------+ KSTACKTOP             
     | 0x00000 | old SS   |     " - 4
     |      old ESP       |     " - 8
     |     old EFLAGS     |     " - 12
     | 0x00000 | old CS   |     " - 16
     |      old EIP       |     " - 20 <---- ESP 
     +--------------------+             
```
然后处理器读取 IDT 中的第0项并设置 CS 和 EIP指向第0项中断处理程序的地址。而对于缺页异常，还会压入一个error code，这一步不是处理器做的工作，而是中断处理程序做的。

处理器可以处理用户模式或者内核模式下的异常/中断。如果是内核模式下发生了异常/中断，则因为不需要切换堆栈，只需要内核栈压入 EFLAGS, CS, EIP的值即可，不用压入SS和ESP的值。通过这种机制，处理器可以优雅的处理内核代码出现的嵌套的异常/中断。

```
     +--------------------+ <---- old ESP
     |     old EFLAGS     |     " - 4
     | 0x00000 | old CS   |     " - 8
     |      old EIP       |     " - 12
     +--------------------+            
```

## 4.4 系统调用
在 JOS 中，使用 `int $0x30` 指令引起处理器中断完成系统调用。用户进程通过系统调用让内核为其完成一些功能，如打印输出cprintf，当内核执行完系统调用后，返回用户进程继续执行。

注意系统调用的中断门描述符的DPL必须设置为3，允许用户调用。如前面提过，在int n这类软中断调用时会检查 CPL 和 DPL，只有当前的 CPL 比要调用的中断的 DPL值小或者相等才可以调用，否则就会产生`General Protection`。用户程序通过 `lib/syscall.c`触发系统调用，最终由`kern/trap.c`中的trap_dispatch()统一分发，并调用`kern/syscall.c`中的syscall()处理。其参数必须设置到寄存器中，其中系统调用号存储在%eax，其他参数依次存放到 %edx, %ecx, %ebx, %edi, 和%esi，返回值通过 %eax 来传递。

```
 asm volatile("int %1\n"
             : "=a" (ret)
             : "i" (T_SYSCALL),
               "a" (num),
               "d" (a1),
               "c" (a2),
               "b" (a3),
               "D" (a4),
               "S" (a5)
             : "cc", "memory");
```

注意，在kern/trap.c 中对syscall()的返回值要保存在Trapframe的tf_regs.reg_eax字段中，这样在返回用户程序执行时， env_pop_tf将reg_eax值弹出到 %eax寄存器中，从而实现了返回值传递。

# 5 用户模式开启
用户程序的入口在 `lib/entry.S`，在其中设置了 envs，pages，uvpt等全局变量以及_start符号。_start是整个程序的入口，链接器在链接时会查找目标文件中的_start符号代表的地址，把它设置为整个程序的入口地址，所以每个汇编程序都要提供一个_start符号并且用.globl声明。entry.S中会判断 USTACKTOP 和 寄存器esp的值是否相等，若相等，则表示没有参数，则会默认在用户栈中压入两个0，然后调用libmain函数。当然lab 3中的用户程序代码都没有传参数的。

而libmain()则需要设置 thisenv 变量(因为测试的用户程序里面会引用thisenv的一些字段)，然后调用umain函数，而umain函数就是我们在 `user/hello.c`这些文件中定义的主函数。最后，执行完umain，会调用 exit退出。exit就是调用了系统调用 sys_env_destroy，最终内核通过 `env_destroy()`销毁用户进程并回到monitor()。

内存保护可以确保用户进程中的bug不能破坏其他进程或者内核。当用户进程试图访问一个无效的或者没有权限的地址时，处理器就会中断进程并陷入到内核，若错误可修复，则内核就修复它并让用户进程继续执行；如果无法修复，那么用户进程就不能继续执行。许多系统调用接口运行把指针传给 kernel，这些指针指向用户buffer，为防止恶意用户程序破坏内核，内核需要对用户传递的指针进行权限检查。内存保护由 user_mem_check()和 user_mem_assert()实现。检查用户进程访存权限，并检查是否越界。



