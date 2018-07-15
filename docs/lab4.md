# 1 多处理器启动流程
## 1.1 多处理器支持
为了支持多处理器，首先需要知道多处理器的配置，这个配置通常是存储在BIOS里面。BIOS需要传递配置信息给多个处理器，同时需要能复原多处理器及其相关组件，多处理器的BIOS也要扩展功能，增加MP配置。

SMP是指所有处理器都是平等的，包括内存对称和IO对称。内存对称指所有处理器都共享同样的内存地址空间，访问相同的内存地址。而IO对称则是所有处理器共享相同的IO子系统(包括IO端口和中断控制器)，任一处理器可以接收任何源的中断。虽然处理器都平等的，但是可以分为BSP(启动处理器)和AP(应用处理器)，BSP负责初始化其他处理器，至于哪个处理器是BSP则是由BIOS配置决定的。

APIC（Advanced Programmable Interrupt Controller）基于分布式结构，分为两个单元，一个是处理器内部的Local APIC单元(LAPIC)，另一个是IO APIC单元，它们两个通过Interrupt Controller Communications (ICC) 总线连接。APIC作用一是减轻了内存总线中关于中断相关流量，二是可以在多处理器里面分担中断处理的负载。

LAPIC提供了 interprocessor interrupts (IPIs),它允许任意处理器中断其他处理器或者设置其他处理器，有好几种类型的IPIs，如INIT IPIs和STARTUP IPIs。每个LAPIC都有一个本地ID寄存器，每个IO APIC都有一个 IO ID寄存器，这个ID是每个APIC单元的物理名称，它可以用于指定IO中断和interprocess中断的目的地址。因为APIC的分布式结构，LAPIC和IO APIC可以是独立的芯片，也可以将LAPIC和CPU集成在一个芯片，如英特尔奔腾处理器（735\90, 815\100），而IO APIC集成在IO芯片，如英特尔82430 PCI-EISA网桥芯片。集成式APIC和分离式APIC编程接口大体是一样的，不同之处是集成式APIC多了一个STARTUP的IPI。


在SMP系统中，每个CPU都伴随有一个LAPIC单元，LAPIC用于传递和响应系统中断，LAPIC也为与它连接的CPU提供了一个唯一ID，在lab4中，我们只用到LAPIC的一些基本功能：

- 读取LAPIC标识来告诉我们当前代码运行在哪个CPU上(见cpunum()）。
- 从BSP发送 STARTUP IPI到AP，用于启动AP，见（lapic_startup())。
- 在part C，我们变成LAPIC内置的计时器来触发时钟中断支持抢占式多任务(见apic_init())。

处理器访问它的LAPIC使用的是 MMIO，在MMIO里，一部分内存硬连线到了IO设备的寄存器，因此用于访问内存的load/store指令可以用于访问IO设备的寄存器。比如我们在实验1中用到 0xA0000开始的一段内存作为VGA显示缓存。LAPIC所在物理地址开始于0xFE000000(从Intel的文档和测试看这个地址应该是0xFEE00000)，在JOS里面内核的虚拟地址映射从KERNBASE(0xf00000000)来说，这个地址太高了，于是在JOS里面在MMIOBASE(0xef800000）地址处留了4MB空间用于MMIO，后面实验会用到更多的MMIO区域，为此我们要映射好设备内存到MMIOBASE这块区域，这个过程有点像`boot_alloc`，注意映射范围判断。接下来完成作业1，见代码。

```
  *    MMIOLIM ------>  +------------------------------+ 0xefc00000      --+
  *                     |       Memory-mapped I/O      | RW/--  PTSIZE
  * ULIM, MMIOBASE -->  +------------------------------+ 0xef800000
```

## 1.2 AP启动流程

在启动AP前，BSP首先要收集多处理器系统的信息，比如CPU数目，CPU的APIC ID和LAPIC单元的MMIO地址。`kern/mpconfig.c`的mp_init()函数通过读取驻留在BIOS内存区域中的MP配置表来获取这些信息。

boot_aps()函数驱动AP启动进程。AP以实模式启动，很像`boot/boot.S`中那样，boot_aps()将AP entry代码拷贝到实模式可寻址的一个地址，与bootloader不同的是，我们可以控制AP开始执行代码的位置，我们将AP entry代码拷贝到 0x7000(MPENTRY_PADDR)，当然其实你拷贝到640KB之下的任何可用的按页对齐的物理地址都是可以的。

之后，boot_aps()通过向AP的LAPIC发送STARTUP IPIs依次激活AP，并带上AP要执行的初始入口地址CS:IP（MPENTRY_PADDR)。入口代码在 kern/mpentry.S，跟`boot/boot.S`非常相似。在简单的设置后，它将AP设置为保护模式，并开启分页，然后调用 mp_main()里面的C设置代码。boot_aps()会等待AP在其CpuInfo中的cpu_status字段发出CPU_STARTED 标志，然后继续唤醒下一个AP。为此需要将 MPENTRY_PADDR 这一页内存空出来。

接下来我们要分析下加入多处理器支持后JOS的启动流程，新加的几个相关函数是 `mp_init()`, `lapic_init()`以及`boot_aps()`。

### 多处理器配置搜索和初始化
mp_init()主要是搜索多处理器配置信息，要怎么找呢，首先是按下面的顺序找`MP Floating Pointer Structure`(简写为MPFPS)。

- 1 去Extended BIOS Data Area (EBDA)的前1KB处
- 2 去系统base memory的最后1KB找
- 3 去BIOS的只读内存空间： 0xE0000 和 0xFFFFF 之间找(代码里面用的是 0xF0000 到0xFFFFF位置)。


```
+------------------+  <- 0x00100000 (1MB)
|     BIOS ROM     |
+------------------+  <- 0x000F0000 (960KB)
|  16-bit devices, |
|  expansion ROMs  |
+------------------+  <- 0x000C0000 (768KB)
|   VGA Display    |
+------------------+  <- 0x000A0000 (640KB)
|                  |
|    Low Memory    |
|                  |
+------------------+  <- 0x00000000
```

而EBDA的起始位置可以从 BIOS 的 40:0Eh 处找到，也就是 0x40 << 4 + 0x0Eh = 0x40Eh 处找EBDA的起始位置。在测试中，我的测试机里面显示该值为 `0x9fc0`，故而会先在EBDA的 `0x9fc00`(左移4位得到物理地址) 到 0xA0000之间找。在BIOS 的 40:13h 处可以找到base memory大小值减1KB的值，这个值是 以KB为单位的，比如我的测试环境显示该值为 0x9fc00，则base memory为0x9fc00 + 1K = 0xA0000 也就是640KB。由此我们这里EBDA的前1KB和base memory的最后1KB其实是同一个内存区域。如果前面两个位置找不到，则会去0xE0000h到0xFFFFFh区域找。在测试环境中在位置3找到了MPFPS，这里的校验方式是 **mp->signature == "__MP__" 且mp结构体的所有字段之和为0**。

找到了MPFPS后，我们要根据它的配置去找 `MP Configuration Table`(MPCT)，发现 MPFPS中的 `physical address`值为 0xf64d0，即表示 MPCT地址在0xf64d0开始的一段BIOS ROM里面。可以调试发现我们测试机里面的MPCT的版本为1.4，LAPIC的基地址为 `0xfee00000`，配置项有20个，而这里的配置项又分为 `Processor, Bus，IO APIC，IO Interrupt Assignment以及Local Interrupt Assignment`这五种类型。对于处理器类型，这里有几个比较重要的字段，其中有cpu的几个标识，其中一个BP如果设置为1，表示这个处理器是启动处理器BSP。另一个是EN，为1表示启用，为0表示禁用。还有一个LAPIC ID字段，用于标识该处理器里面的LAPIC的ID，ID是从0开始编号的。JOS里面最多支持8个CPU，多余的CPU不会启用。

在我们测试的时候`make qemu CPUS=n`，其中的n就是指定的模拟的CPU的数目，指定了几个我们就能找到几个CPU的MPCT配置项。为维护CPU状态，JOS内核中维护了一个cpus的数组和CpuInfo结构体。

```
// Per-CPU state
struct CpuInfo {
    uint8_t cpu_id;                 // Local APIC ID; index into cpus[] below
    volatile unsigned cpu_status;   // The status of the CPU
    struct Env *cpu_env;            // The currently-running environment.
    struct Taskstate cpu_ts;        // Used by x86 to find stack for interrupt
};

// Initialized in mpconfig.c
extern struct CpuInfo cpus[NCPU];
```
找到配置后，接着会设置BSP为falg为BP的处理器，并将其状态设置为 CPU_STARTED。接下来开始初始化LAPIC。

### lapic_init()
因为LAPIC的起始地址默认是在物理地址0XFEE00000，为了方便访问，JOS将这地址通过MMIO映射到了虚拟地址MMIOBASE。映射完成后，我们就可以用lapic这个虚拟地址来访问和设置LAPIC了。lapic_init()主要对LAPIC的一些寄存器进行设置，包括设置ID，version，以及禁止所有CPU的NMI(LINT1)，BSP的LAPIC要以Virtual Wire Mode运行，开启BSP的LINT0，以用于接收8259A芯片的中断等。

### pic_init()
pic_init()用于初始化8259A芯片的中断控制器。8259A芯片是一个中断管理芯片，中断来源除了来自硬件本身的NMI中断以及软件的INT n指令造成的软件中断外，还有来自外部硬件设备的中断(INTR)，这些外部中断时可以屏蔽的。而这些中断的管理都是通过PIC（可编程中断控制器）来控制并决定是否传递给CPU，JOS中开启的INTR中断号有1和2。

### boot_aps()
接下来是启动AP了。首先通过memmove将mpentry的代码拷贝到 MPENTRY_PADDR (0x7000)处(其中习题2要将0x7000对应的一页设置为已用，不要加入到空闲链表)，设置好对应该cpu的堆栈栈顶指针，然后调用`kern/lapic.c`中的`lapic_startap()`开始启动AP。

lapic_startap()完成lapic的设置，包括设置warm reset vector指向mpentry代码起始位置，发送STARTUP IPI以触发AP开始运行mpentry代码，并等待AP启动完成，一个AP启动完成后再启动下一个。

那么mpentry代码就是在`kern/mpentry.S`中了，它的作用类似bootloader，最后是跳转到mp_main()函数执行初始化。mpentry.S 在加载GDT和跳转时用到了MPBOOTPHYS宏定义，因为mpentry.S代码是加载在 KERNBASE之上的，在CPU实模式下是无法寻址到这些高地址的，所以需要转换为物理地址。而boot.S代码不用转换，是因为它们本身就加载在实模式可以寻址的`0x7c00-0x7dff`。后面的流程跟boot.S类似，也是开启保护模式和分页。因为mpentry的代码加载到了 0x7000，需要在 `page_init()` 中将这一页从page空闲链表去除，见作业2.


```
#define MPBOOTPHYS(s) ((s) - mpentry_start + MPENTRY_PADDR)
```

**此时用的页目录跟 `kern/entry.S` 时一样，用的也是 entry_pgdir，因为此时的运行指令在低地址，并没有在 `kern_pgdir` 建立映射。** 最后通过`call`指令跳转到mp_main()函数执行，注意下这里用了间接call，为什么不是直接`call $mp_main`呢? 这里之所以不直接call，是因为直接call用的是相对地址，即将 EIP 设置为 `EIP + call后跟的一个相对地址`，比如这里我们的call指令的地址为`0x7050`，然后EIP会指向下一条地址0x7055，call地址会被设置为 `0x7050 + 5 +  0xffffa609 = 0x10000165e`，地址溢出后变成`0x165e`，而这个地址内容是`0x80050044`，可知0x165e处对应的指令是 0x44，也就是 `inc %esp`，当然这一步不会报错，接着下一条指令在 0x165f，指令对应的是 `00 05 80 44 00 05`，即`add %al, 0x05004480`，则此时访问地址`0x05004480`会报错，因为此时用的是`entry_pgdir`，还没有建立该地址的页面映射。

 ```
 ## 正确方式
 mov $mp_main, %eax; 
 call *%eax;
 
 ## 错误方式
 call mp_main
 f0105bc8:       e8 09 a6 ff ff          call   f01001d6 <mp_main>
 
 (gdb) x /16x 0x165e
0x165e:	0x80050044	0x90050044	0xa0050044	0xb0050044
 ``` 

mp_main()函数先是加载了kern_pgdir到CR3中，然后调用下面几个方法，包括前面提过的lapic_init(),以及为每个CPU初始化进程相关内容和中断相关内容，最后设置cpu状态为 CPU_STARTED 让 BSP 去启动下一个CPU。注意到这里用到了xchg函数来设置cpu状态，该函数用到xchgl来交换addr存储的值和newval，并将addr原来存储的值存到result变量中返回，指令中的`lock;`用于保证多处理器操作的原子性。

```
void
mp_main(void)
{
	// We are in high EIP now, safe to switch to kern_pgdir 
	lcr3(PADDR(kern_pgdir));
	lapic_init();
	env_init_percpu();
	trap_init_percpu();
	xchg(&thiscpu->cpu_status, CPU_STARTED); // tell boot_aps() we're up
	for (;;);
}

static inline uint32_t
xchg(volatile uint32_t *addr, uint32_t newval)
{
    uint32_t result;

    // The + in "+m" denotes a read-modify-write operand.
    asm volatile("lock; xchgl %0, %1"
             : "+m" (*addr), "=a" (result)
             : "1" (newval)
             : "cc");
    return result;
}
```

## 1.3 CPU初始化

多核CPU需要各自优化，每个CPU都有自己的一些初始化变量，如下：

### 内核栈
每个cpu都要有一个内核栈，以免互相干扰。`percpu_kstacks[NCPU][KSTKSIZE]`用于保存栈空间。

### TSS和TSS描述符
每个CPU都要有自己的TSS(任务状态段)和TSS描述符。CPU i的TSS存储在`cpus[i].cpu_ts`，而TSS描述符在GDT中的索引是`gdt[(GD_TSS0 >> 3) + i]`，之前实验用到的全局变量 ts 不再需要了。

### 当前进程指针
每个CPU都要有自己运行的当前CPU运行的当前进程(Env)的指针curenv，存储在 `cpus[cpunum()].cpu_env`或`thiscpu->cpu_env`。

### 系统寄存器
所有寄存器，包括系统寄存器都是每个CPU独有的。因此lcr3，ltr，lgdt，lidt 这些指令在每个CPU上都要执行一次，其中`env_init_per_cpu()`和`trap_init_per_cpu()`就是用于这个目的。

具体实现见作业3-4。

## 1.4 内核锁
在mp_main中初始化AP后，我们开始spin循环。在AP进一步操作前，我们需要解决多个CPU同时运行内核代码时的资源竞争问题，因为多进程同时运行内核代码，会影响内核中的数据正确性。最简单的方式是使用`big kernel lock`(大内核锁)，进程在进入内核时获取大内核锁，回到用户态时释放锁。在该模式下，进程可以并发的运行在空闲的CPU上，但是同时只能有一个进程运行在内核态，其他进程想进入内核态必须等待。

大内核锁在`kern/spinlock.h`中定义，可以通过`locker_kernel()`和`unlock_kernel()`来进行加锁和解锁。我们需要在下面几处位置加锁和释放锁。

- 在`i386_init()`中，在BSP唤醒AP前加锁。
- 在`mp_main()`中，初始化AP后加锁，并调用`sched_yield()`在该AP上运行进程。
- 在`trap()`中，进程从用户态陷入时加锁。
- 在`env_run()`中，进程切换到用户态之前释放锁。

这样，我们在BSP启动AP前，先加了锁。AP经过mp_main()初始化后，因为此时BSP持有锁，所以AP的`sched_yield()`需要等待，而当BSP执行调度运行进程后，会释放锁，此时等待锁的AP便会获取到锁并执行其他进程。


## 1.5 轮转调度
轮转调度(round-robin)在`sched_yield()`中完成，核心思想就是从进程列表中找到一个状态为 ENV_RUNNABLE 的进程运行。注意，不能同时有两个CPU运行同一个进程，这个可以根据进程状态进行判断，已经运行的进程状态为 ENV_RUNNING 。如果在列表中找不到ENV_RUNNABLE的进程，而之前运行的进程又处于ENV_RUNNING状态，则可以继续运行之前的进程。

修改了`kern/init.c`运行3个`user_yield`进程，可以看到输出如下：

```
# make qemu CPUS=2
Hello, I am environment 00001000.
Hello, I am environment 00001001.
Back in environment 00001000, iteration 0.
Hello, I am environment 00001002.
Back in environment 00001001, iteration 0.
Back in environment 00001000, iteration 1.
Back in environment 00001002, iteration 0.
Back in environment 00001001, iteration 1.
Back in environment 00001000, iteration 2.
Back in environment 00001002, iteration 1.
Back in environment 00001001, iteration 2.
Back in environment 00001000, iteration 3.
Back in environment 00001002, iteration 2.
Back in environment 00001001, iteration 3.
Back in environment 00001000, iteration 4.
Back in environment 00001002, iteration 3.
All done in environment 00001000.
[00001000] exiting gracefully
[00001000] free env 00001000
Back in environment 00001001, iteration 4.
Back in environment 00001002, iteration 4.
All done in environment 00001001.
All done in environment 00001002.
[00001001] exiting gracefully
[00001001] free env 00001001
[00001002] exiting gracefully
[00001002] free env 00001002
```
流程如下：

- BSP先加载3个进程，并设置为ENV_RUNNBALE状态。
- BSP先唤醒AP，由于BSP先在i386_init时持有内核锁，所以BSP先运行进程1 0x1000，运行进程时 env_run() 切换到用户态前会释放内核锁，此时等待锁的AP开始运行 `sched_yield`，这样 AP 会开始运行进程2 0x1001，开始运行后释放内核锁。

- BSP打印出进程号后调用了`sys_yield()`，陷入到内核的trap()里面会加内核锁，所以等到AP开始运行进程2且打印了进程号后，BSP此时运行进程3。此后两个CPU轮流调度可运行的三个进程。

## 1.6 创建进程的系统调用
Unix提供了fork()系统调用创建进程，Unix拷贝了调用进程(父进程）的整个地址空间用于创建新进程(子进程），在用户空间看来他们的唯一区别就是进程ID不同。在父进程中，fork()返回子进程ID，而在子进程中，fork()返回0。默认情况下父子进程都有自己的私有地址空间，且它们对内存修改互不影响。

在JOS中我们要提供几个不同的系统调用用于创建进程，这也是Unix早期实现fork()的方式，下一节会讨论使用 COW 技术实现的新的fork()。

### sys_exofork
这个系统调用创建了一个几乎空白的新的进程，它没有任何东西映射到其地址空间的用户部分，且它不可运行。这个新的进程与父进程有意义的寄存器状态，在父进程中，它返回子进程的envid，而在子进程中，它返回0。由于sys_exofork初始化将子进程标记为ENV_NOT_RUNNABLE，因此sys_exofork不会返回到子进程，只有父进程用sys_env_set_status将其状态设置 ENV_RUNNABLE 后，子进程才能运行。

### sys_env_set_status
设置指定的进程状态为 ENV_NOT_RUNNABLE 或者 ENV_RUNNABLE，用于标记进程可以开始运行。

### sys_page_alloc
用于分配一页物理内存并将其映射到指定的虚拟地址。不同于page_alloc，sys_page_alloc不仅分配了物理页，而且要通过page_insert()将分配的物理页映射到虚拟地址va。

### sys_page_map
从一个进程的地址空间拷贝一个页面映射(**注意，不是拷贝页的内容**）到另一个进程的地址空间。其实就是用于将父进程的某个临时地址空间如UTEMP映射到子进程的新分配的物理页，方便父进程访问子进程新分配的内存以拷贝数据。

### sys_page_unmap
取消指定进程的指定虚拟地址处的页面映射以下次重复使用。

所有上面的系统调用都接收进程ID参数，如果传0表示指当前进程。通过进程ID得到进程env对象可以通过函数 `kern/env.c` 中的 envidenv() 实现。

在 user/dumbfork.c中有一个类似unix的fork()的实现，它使用了上面这几个系统调用运行了子进程，子进程拷贝了父进程的地址空间。父子进程交替切换，最后父进程在循环10次后退出，而子进程则是循环20次后退出。

```
void
duppage(envid_t dstenv, void *addr)
{
    int r;

    // This is NOT what you should do in your fork.
    if ((r = sys_page_alloc(dstenv, addr, PTE_P|PTE_U|PTE_W)) < 0)
        panic("sys_page_alloc: %e", r); 
    if ((r = sys_page_map(dstenv, addr, 0, UTEMP, PTE_P|PTE_U|PTE_W)) < 0)
        panic("sys_page_map: %e", r); 
    memmove(UTEMP, addr, PGSIZE);
    if ((r = sys_page_unmap(0, UTEMP)) < 0)
        panic("sys_page_unmap: %e", r); 
}
```

user/dumbfork.c 中的dumbfork()具体实现流程是这样的：

- 1）先通过 sys_exofork() 系统调用创建一个新的空白进程。
- 2）然后通过duppage拷贝父进程的地址空间到子进程中。用户进程地址空间开始位置是UTEXT（0x00800000) ，结束位置是 end。duppage是一页页拷贝的，它将父进程的addr开始的一页物理内存内容拷贝到子进程dstenv的对应的页中。
- 3) 完成父进程到子进程内存数据的拷贝。
	- 3.1）先通过sys_page_alloc为子进程addr开始的一页内容分配一个物理页并完成映射，此时，分配的物理页还是空的，没有数据。然后通过 sys_page_map 将子进程va开始的这分配好的物理页映射到父进程的UTEMP地址处(0x00400000)，这么做的目的就是为了在父进程中访问到子进程新分配的物理页。
	- 3.2)接下来，通过memmove函数将父进程addr处的一页数据拷贝到了UTEMP中，而因为前面看到UTEMP已经映射到了子进程的那页内存，所以最终效果就是将父进程的addr处的一页内存数据拷贝到子进程的addr对应的那页内存完成数据的复制。
	- 3.3)最后通过 sys_page_unmap 取消父进程在UTEMP的映射以下次使用，当然还有个重要目的是预防父进程误操作到子进程的内存数据。


# 2 写时复制(Copy On Write)
前面实现fork是直接将父进程的数据拷贝到了子进程，这是Unix系统最初采用的方式，但是这样有个问题就是会造成资源浪费，很多时候我们fork一个子进程，接着是直接exec替换子进程的内存直接执行另一个程序，子进程在exec之前用到父进程的内存数据很少。

于是后续的Unix版本优化了fork，利用了虚拟内存硬件支持的方式，fork时拷贝的是地址空间而不是物理内存数据，这样，父子进程各自的地址空间都映射到同样的内存数据，共享的内存页会被标记为只读。当父子进程有一方要修改共享内存时，此时会报`page fault`错误，此时Unix内核会为报错的进程分配一个新的物理页，并拷共享内存页的数据到新分配的物理页中。执行exec时，只需要拷贝堆栈这一个页面即可。

## 2.1 用户程序页面错误处理
为了实现写时复制，首先要实现用户程序页面错误处理功能。基本流程是：

- 1）用户进程通过 set_pgfault_handler(handler) 设置页面错误处理函数。
- 2）函数set_pgfault_handler中为用户程序分配异常栈，通过系统调用sys_env_set_pgfault_upcall 设置通用的页面错误处理调用入口。
- 3）**当用户进程发生页面错误时，陷入内核**。内核先判断该进程是否设置了 env_pgfault_upcall，如果没有设置，则报错。如果设置了，则切换用户进程栈到异常栈，设置异常栈内容，然后设置EIP为 env_pgfault_upcall 地址，**切回用户态执行 env_pgfault_upcall 函数(即_pgfault_upcall)**。
- 4）**env_pgfault_upcall作为页面错误处理函数的入口函数，它在用户态运行**。先调用步骤1中注册的页面错误处理函数，然后再恢复进程在页面错误之前的栈内容，并切回常规栈，跳转到页面错误之前的地方继续运行。

### 设置用户级页面错误处理函数
前面提到，新的fork并不直接拷贝内存数据，而是先对共享的内存页设置一个特殊标记，然后在父子进程的一方写共享内存发生页面错误时，内核捕获异常并分配新的页和拷贝数据。这里首先要实现的是对用户级的页面错误的捕获和处理。

COW只是用户级页面错误处理的许多可能用途之一。大多数Unix内核最初只映射新进程的堆栈，随着堆栈消耗增加，访问尚未映射的堆栈地址会导致页面错误，内核捕获错误后会分配并映射附加的堆栈页面。典型的Unix内核必须跟踪进程空间的每个区域发生页面错误时要采取的操作。例如，堆栈区域中的错误通常会分配并映射新的物理内存页面，程序的BSS区域中的错误通常会分配一个新页面，填充零并映射它。而可执行代码中导致的页面错误将触发内核从磁盘读取可执行文件的相应页面，然后映射它。

为了处理用户进程页面错误，用户进程需要设置一个页面错误处理函数，新增加一个系统调用`sys_env_set_pgfault_call`来设置Env结构体的 env_pgfault_upcall 字段即可。

### 用户进程异常栈和常规栈
而为了处理用户级页面错误，JOS采用了一个用户异常栈UXSTACKTOP(0xeec00000)，注意用户进程的常规栈用的是USTACKTOP(0xeebfe000)。当用户进程发生页面错误时，内核会切换到异常栈，异常栈大小也是PGSIZE。从用户常规栈切换到异常栈的过程有点像发生中断/异常时从用户态进入内核时的堆栈切换。

当运行在异常栈时，用户级页面错误处理函数可以调用JOS的常规系统调用去映射新的页面，以期修复导致页面错误的问题。当用户级页面错误处理函数处理完成后，再通过一段汇编代码返回到常规堆栈存储的发生页面错误的地址处继续运行。

需要支持用户级页面错误处理的用户进程都需要为它的异常栈分配内存，可以使用前面用过的sys_page_alloc分配内存。

### 调用用户页面错误处理函数
修改`kern/trap.c`中的页面错误处理代码以支持用户进程的页面错误处理。如果用户进程没有注册页面错误处理函数，则跟之前一样返回错误即可。而如果设置了页面错误处理函数，则需要在异常栈中压入下面内容以记录出错状态，这些内容正好构成了一个UTrapframe结构体，方便统一处理，接着设置EIP为env_pgfault_upcall函数地址，并将进程的堆栈切换到异常栈，然后开始运行页面错误处理函数。

页面错误处理函数是在`lib/pfentry.S`中定义的，它首先要执行用户程序中定义的pgfault_handler函数，然后再回到程序出错位置继续运行。

**需要注意的是，如果用户进程已经运行在异常栈了，此时又发生嵌套页面错误，则需要在`tf->tf_esp`而不是从UXSTACKTOP压入异常数据，而且这种情况下，你要保留一个空的4字节，再压入UTrapframe。**要检查用户进程是否运行在异常栈，可以检查 tf->tf_esp 是否在区间 [UXSTACKTOP-PGSIZE, UXSTACKTOP-1]。

```
                    <-- UXSTACKTOP
trap-time esp   // 页面错误时用户栈的地址
trap-time eflags
trap-time eip
trap-time eax       start of struct PushRegs
trap-time ecx
trap-time edx
trap-time ebx
trap-time esp
trap-time ebp
trap-time esi
trap-time edi       end of struct PushRegs
tf_err (error code)
fault_va            <-- %esp when handler is run
```

### 回到页面错误处继续执行
在执行完页面错误处理函数后，需要回到用户进程之前出错的位置继续执行，这里需要完成 `lib/pfentry.S`中的`_pgfault_upcall`函数。

这个函数做的工作就是将异常栈切换到常规栈，重新设置 EIP，注意之前页面出错地址存储在 fault_va 中。这里要添加代码如下，此时esp指向的是前一节的UTrapframe的地址，这里做的工作主要是：

- 将用户进程的常规栈当前位置减去4字节，然后将用户进程页面错误时的EIP存储到该位置。这样恢复常规栈的时候，栈顶存储的是出错时的EIP。
- 然后将异常栈中存储的用户进程页面错误时的通用寄存器和eflags寄存器的值还原。
- 然后将异常栈中存储的esp的值还原到esp寄存器。
- 最后通过ret指令返回到用户进程出错时的地址继续执行。(ret指令执行的操作就是将弹出栈顶元素，并将EIP设置为该值，此时正好栈顶是我们在之前设置的出错时的EIP的值）
- **现在可以看到如果发生嵌套页错误为什么多保留4个字节了，这是因为发生嵌套页错误时，此时我们的trap-time esp存储的是异常栈，此时会将trap-time的EIP的值会被设置到esp-4处，如果不空出4字节，则会覆盖原来的esp值了。**

```
movl 0x28(%esp), %ebx # trap-time时的eip，注意UTrapframe结构
subl $0x4, 0x30(%esp) 
movl 0x30(%esp), %eax 
movl %ebx, (%eax)    # 将trap-time的eip拷贝到trap-time esp-4处
addl $0x8, %esp

popal 

addl $0x4, %esp # 设置eflags
popfl

popl %esp     # 将栈顶地址弹出到esp，此时栈顶值是用户进程出错时的eip值
ret           
```

最后还要完成`lib/pgfault.c`中的`set_pgfault_handler`函数，用于为用户进程分配异常栈以及页面错误处理函数 env_pgfault_upcall 的初始化设置。


## 2.2 实现写时复制fork
完成上一节准备工作后，开始实现COW的fork，fork实现的流程如下：

- 1）父进程设置pgfault()函数为页面错误处理函数，用到前面的 set_pgfault_handler 函数。
- 2）父进程调用 sys_exofork() 创建一个空白子进程。
- 3）对父进程在UTOP之下的可写或者COW的物理页，父进程调用duppage，duppage会将这些页面设置为COW映射到子进程的地址空间，同时，也要将父进程本身的页面重新映射，将页面权限设置为COW(注：子进程的COW设置要在父进程之前)。duppage将父子进程相关页面权限设置为不可写，且在avail字段设置为COW，用于区分只读页面和COW页面。异常栈不以这种方式重新映射，需要在子进程分配一个新的页面给异常栈用。fork()还要处理那些不是可写的且不是COW的页面。
- 4）父进程设置子进程的页面错误处理函数。
- 5）父进程标识子进程状态为可运行。

当父子进程中任意一个试图修改一个还没有写过的COW页面，会触发页面错误，开始下面流程：

- 1）内核发现用户程序页面错误后，转至_pgfault_upcall处理，而_pgfault_upcall会调用pgfault()。
- 2）pgfault()检查这是一个写错误(错误码中的FEC_WR)且页面权限是COW的，如果不是则报错。
- 3）pgfault()分配一个新的物理页，并映射到一个临时位置，然后将出错页面的内容拷贝到新的物理页中，然后将新的页设置为用户可读写权限，并映射到对应位置。

fork()，pgfault(),duppage()三个函数的具体实现见作业12。完成后`make run-forktree`，正常应该输出下面的内容(顺序可能不同)：

```
1000: I am ''
1001: I am '0'
2000: I am '00'
2001: I am '000'
1002: I am '1'
3000: I am '11'
3001: I am '10'
4000: I am '100'
1003: I am '01'
5000: I am '010'
4001: I am '011'
2002: I am '110'
1004: I am '001'
1005: I am '111'
1006: I am '101'
```

forktree这个程序比较有意思，它先创建两个子进程打印第一层 0， 1，然后子进程再分别创建子进程打印一棵树出来，比如两层是这样的，打印结果是 `'', 0, 1, 00, 01, 10, 11`。

```
		 ‘’
		/ \
	  0   1
     /\  /\
    0 1  0 1
```

# 3 抢占式调度和进程间通信
## 3.1 时钟中断
最后一部分是通过时钟中断来完成抢占式调度。运行`make run-spin`可以看到子进程死循环占用了CPU，没法切换到其他进程了，现在需要通过时钟中断来强制调度。**时钟中断属于可屏蔽中断，可以通过 eflags 寄存器的IF位来控制，注意由int指令触发的软件中断不受eflags寄存器的控制，它是不可屏蔽中断，此外NMI也属于不可屏蔽中断。**

外部中断通常称之为 IRQ，IRQ到中断描述符表的入口不是固定的。不过在 pic_init 中我们将IRQ的0-15映射到了IDT的[IRQ_OFFSET, IRQ_OFFSET+15]。其中IRQ_OFFSET为32，所以IRQ在IDT中范围为[32, 47]，共16个。JOS中对中断做了简化处理，在内核态时外部中断是禁止的，在用户态时才会开启。中断开启和禁止是通过eflags寄存器的 FL_IF 位来控制，为1表示开启中断，为0则禁止中断。

接下来类似实验3那样，设置中断号和中断处理程序。**注意在实验3中我将istrap基本都设置为1了，虽然那时候不影响实验结果，在实验4这里必须要全部将istrap值设为0。因为JOS中的这个istrap设为1就会在开始处理中断时将FL_IF置为1，而设为0则保持FL_IF不变，设为0才能通过trap()中对FL_IF的检查。**最后在 trap() 函数中处理 IRQ_TIMER中断，调用`lapic_eio()`和`sched_yield()`即可。

## 3.2 进程间通信(IPC)
最后要完成进程间通信，常见的一个IPC例子就是管道。实现IPC有很多方式，哪种方式最好至今仍有争论，JOS中会实现一种简单的IPC机制。需要完成 sys_ipc_try_send() 和 sys_ipc_recv() 两个系统调用，以及封装了这两个系统调用的库函数实现。

JOS IPC中的消息包括两个部分：一个32位的值以及一个可选的页面映射。消息中包含这个页面映射是为了传输更多的数据以及实现进程间共享内存。

进程调用 sys_ipc_recv() 接收消息，调用 sys_ipc_try_send() 发送消息。如果要发送页面映射，则调用时设置srcva参数，表示要将srcva处的页面映射共享给接收进程。而接收进程的 sys_ipc_try_recv() 如果希望接收页面映射，则会提供一个 dstva 参数。如果发送进程和接收进程都没有设置参数表示希望传输页面映射，则不传输。内核会在接收进程的 env_ipc_perm字段设置接收的页面映射的权限。

任何进程都可以发送消息给其他进程，不需要它们是父子进程。这里的安全由IPC相关系统调用保障，一个进程不能通过发送消息导致另一个进程奔溃，除非接收消息的进程本身存在BUG。

# 4 一些注意点
- 完成作业15后，可以发现stresssched通不过测试，这个有个坑，检查了很久才发现，原来要在 `kern/sched.c`的 `sched_halt(void)` 中去掉 `//sti`的注释，因为在AP启动完成且获得锁且第一次调用 sched_yield()时，如果发现没有可运行进程，会执行sched_halt()导致CPU处于HALT状态。因为我们在bootloader中通过cli关闭了中断的，所以此时需要开启中断，不然AP就一直处于HALT状态而不参与调度了。

- 另外，spin测试不要多加参数如`CPUS=2`，否则会测试失败，因为当父子进程在不同的CPU运行时，此时父进程去销毁子进程会先将子进程设置为 ENV_DYING 状态，而后等子进程调度的时候再自己销毁自己，这会跟要求输出不一样导致通不过测试。

- 一些调试语句要注意输出位置，可能会干扰测试结果，因为作业是根据输出来判定的，最好去掉多余的调试语句来测试。
