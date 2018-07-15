> 继lab1之后，lab2主要是实现内存分页管理。包括物理页管理，虚拟内存管理，内核地址空间等内容，先来看看相关理论知识。

# 1 背景知识

由lab1中可以知道，当前的内存布局如下所示：

![内存布局](https://upload-images.jianshu.io/upload_images/286774-f1f5cf21e3847131.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


其中0~0x3ff是BIOS中断向量表(后面会被设置为中断描述符表IDT)，而启动代码Boot Loader则被加载到了 0x7C00 处，接着 Boot Loader 代码执行后，会将内核代码的ELF文件头读取到 0x10000(64KB) 开始的4KB内存中，然后根据 ELF文件头 将内核代码读取到 0x10000(1MB) 开始的处，然后跳转到 i386_init 函数执行内核初始化操作，包括BSS清零，屏幕显示初始化，然后初始化内存分配(mem_init函数)，内存分配的实现主要在 `kern/pmap.c` 文件中，需要完成其中的相关函数。另外JOS还提供了几个函数给我们测试，如`check_page_free_list() 和check_page_alloc() 函数`。

# 2 页表管理

在做实验之前，再来回顾下x86保护模式下内存管理架构：分段和分页。再来看看虚拟地址(逻辑地址)，线性地址和物理地址之间的区别。

```

           Selector  +--------------+         +-----------+
          ---------->|              |         |           |
                     | Segmentation |         |  Paging   |
Software             |              |-------->|           |---------->  RAM
            Offset   |  Mechanism   |         | Mechanism |
          ---------->|              |         |           |
                     +--------------+         +-----------+
            Virtual(Logical)                   Linear                Physical
```

我们代码中的 C 指针就是虚拟地址中的 offset，通过描述符表和段选择子(selector)，通过分段机制转换为线性地址，因为JOS中设置的段基址为0，所以线性地址就等于offset。在未开启分页之前，线性地址就是物理地址。而在我们开启分页之后，线性地址经过 CPU 的MMU部件的页式转换得到物理地址。

开启分页后，当处理器碰到一个线性地址后，它的MMU部件会把这个地址分成 3 部分，分别是页目录索引(Directory)、页表索引(Table)和页内偏移(Offset)， 这 3 个部分把原本 32 位的线性地址分成了 10+10+12 的 3 个片段。每个页表的大小为4KB（因为页内偏移为12位）。过程如下图所示：

![地址转换流程](https://upload-images.jianshu.io/upload_images/286774-73004835aee1e4bc.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


在lab1中，我们创建了1024个页目录项，虽然只用了2个，每个页目录项大小为4字节，一共占4KB内存。页目录项的结构和页表项的结构基本一致，前20位为物理页索引(ppn），用于定位页表物理地址，通过页表物理地址和页内偏移已经可以找到物理地址了，所以页目录(页表）项的低12位可以用于一些标识和权限控制。各个位含义如下：

* P —— Present，判断对应物理页面是否存在，存在为1，否则为0; 
* W —— Write，该位用来判断对所指向的物理页面是否可写，1可写，0不可写；
* U —— User，该位用来定义页面的访问者应该具备的权限。为1是User权限即可，如果为 0，表示需要高特权级才能访问；
* WT —— 1=Write-through，0=Write-back；
* CD —— Cache Disabled，1为禁用缓存，0不禁用；
* D —— Dirty，是否被修改;
* A —— Accessed，最近是否被访问;
* AVL —— Available，可以被系统程序所使用;
* 0 —— 保留位。

系统在访问一个页面时就会自动地去判断页表的这些位，如果页面不存在或者权限不符，系统就会产生异常，让系统去处理。在启用分页前，页目录所在的物理页面的首地址需要存放到 CR3 寄存器中，这样x86处理器在进行页式地址转换时会自动地从CR3中取得页目录物理地址，然后根据线性地址的高10位取页目录项，由页目录项所存储的地址(高20位)得到页表所在物理页的首地址。然后根据中间10位取得页表项，由页表项所存储的地址(高20位）找到物理页起始地址(Page Frame)，将该地址 + 12位页内偏移得到真正的物理地址。

举例：现在要将线性地址 0xf011294c 转换成物理地址。首先取高 10 位(页目录项偏移)即960(0x3c0)，中间 10 位(页表项偏移)为274(0x112)，偏移地址为1942(0x796)。
首先，处理器通过 CR3 取得页目录，并取得其中的第 960 项页目
录项，取得该页目录项的高 20 位地址，从而得到对应的页表物理页的首地址，再次取得页表中的第274项页表项，并进而取得该页表项的首地址，加上线性地址的低12位偏移地址1942，从而得到物理地址。

由上面也可知道，每个页目录表有1024个页目录项，每个页目录项占用4字节，一个页目录表占4KB内存。而每个页目录项都指向一个有1024个页表项的页表，每个页表项也占用4字节，因此JOS中页目录和页表一共要占用 1025 * 4KB = 4100KB 约4MB的内存。而通常我们说每个用户进程虚拟地址空间为4GB，其实就是每个进程都有一个页目录表，进程运行时将页目录地址装载到CR3寄存器中，从而每个进程最大可以用4GB内存。在JOS中，为了简单起见，只用了一个页目录表，整个系统的线性地址空间4GB是被内核和所有其他的用户程序所共用的。


分页管理中，页目录以及页表都存放在内存中，而由于CPU 和内存速度的不匹配，这样地址翻译时势必会降低系统的效率。为了提高地址翻译的速度，x86处理器引入了地址翻译缓存TLB（旁路转换缓冲）来缓存最近翻译过的地址。当然缓存之后会引入缓存和内存中页表内容不一致的问题，可以通过重载CR3使整个TLB内容失效或者通过 invlpg 指令。

# 3 页面管理
我们知道 JOS 内核代码的虚拟地址是从 0xf0000000 开始的，而映射的物理内存在0~4MB 区间，我们在lab1中也只映射了0~4MB的物理地址，在lab2中我们需要将映射扩展到0~256MB物理内存。另外，如果需要物理地址转虚拟地址可以通过 `KADDR(pa)`，反之用`PADDR(va)`。

在 JOS 系统中，物理页面分配粒度为4KB，对于物理内存的页面管理则是通过链表来实现的。物理页对应的结构体为 `struct PageInfo`。

```
struct PageInfo {
    struct PageInfo *pp_link;
    uint16_t pp_ref;
};
```
代码注释中也有说明，PageInfo不是物理页本身，但是它和物理页面有一一对应的关系。而其中的pp_ref变量用来保存PageInfo对应物理页面的引用次数，在后续的实验中，我们会时常将多个虚拟地址映射到同一个物理地址。当pp_ref为0时，则可以回收这个物理页面了。注意，内核代码映射的物理页面不能被释放，因此它们也不需要引用计数(如UTOP以上的页面映射基本都是内核设置好的)。

需要注意的是，管理物理内存我们用到了 `struct PageInfo *pages`，而通过 `page2pp(page)` 我们可以很轻松的得到该 PageInfo 结构对应的物理内存的起始位置。管理内存，需要对链表 page_free_list 和它实际对应的物理内存一起管理。pages的使用比较巧妙，即可以通过pages[i]来索引第i页，也可以通过链表操作来得到第i页。

**页面操作相关的宏**

```

// 线性地址分为如下三部分
//
// +--------10------+-------10-------+---------12----------+
// | Page Directory |   Page Table   | Offset within Page  |
// |      Index     |      Index     |                     |
// +----------------+----------------+---------------------+
//  \--- PDX(la) --/ \--- PTX(la) --/ \---- PGOFF(la) ----/
//  \---------- PGNUM(la) ----------/
//

// 页目录和页表的一些常量定义
#define NPDENTRIES	1024   //每个页目录的页目录项数目为1024
#define NPTENTRIES	1024   //每个页表的页表项数目也为1024

#define PGSIZE		4096   // 页大小为4096B，即4KB
#define PGSHIFT		12		// log2(PGSIZE)

#define PTSIZE		(PGSIZE*NPTENTRIES) // 一个页目录项映射内存大小，4MB
#define PTSHIFT		22		// log2(PTSIZE)

#define PTXSHIFT	12		 
#define PDXSHIFT	22	

// 页号
#define PGNUM(la)	(((uintptr_t) (la)) >> PTXSHIFT)

// 页目录项索引(高10位)
#define PDX(la)		((((uintptr_t) (la)) >> PDXSHIFT) & 0x3FF)

// 页表项索引（中间10位）
#define PTX(la)		((((uintptr_t) (la)) >> PTXSHIFT) & 0x3FF)

// 页内偏移
#define PGOFF(la)	(((uintptr_t) (la)) & 0xFFF)

// 由索引构造线性地址
#define PGADDR(d, t, o)	((void*) ((d) << PDXSHIFT | (t) << PTXSHIFT | (o)))
```

**页面操作函数**

```
// 由PageInfo结构得到页面物理地址
static inline physaddr_t
page2pa(struct PageInfo *pp)
{
    return (pp - pages) << PGSHIFT;
}

// 由物理地址得到PageInfo结构体
static inline struct PageInfo*
pa2page(physaddr_t pa) 
{
    if (PGNUM(pa) >= npages)
        panic("pa2page called with invalid pa");
    return &pages[PGNUM(pa)];
}

// 与 page2pa 类似，只不过返回的是 PageInfo 结构 pp 所对应的物理页面的内核首地址(虚拟地址)
static inline void*
page2kva(struct PageInfo *pp)
{
    return KADDR(page2pa(pp));
}

```

**待实现函数(下一篇实现和分析)**

```
// 初始化一个页面结构和page_free_list。
void    page_init(void);

// 分配物理页
struct PageInfo *page_alloc(int alloc_flags);

// 释放页面，将页面加入page_free_list
void    page_free(struct PageInfo *pp);

// 将物理页pp映射到虚拟地址va，权限设置为 perm | PTE_P
int page_insert(pde_t *pgdir, struct PageInfo *pp, void *va, int perm);

// 移除虚拟地址va的映射
void    page_remove(pde_t *pgdir, void *va);

// 返回虚拟地址va映射的物理页的PageInfo地址
struct PageInfo *page_lookup(pde_t *pgdir, void *va, pte_t **pte_store);

// 给定页目录地址pgdir，检查虚拟地址va是否可以用页表翻译，若能，返回页表项地址，
// 否则根据需要创建页表项并返回页表项的内核地址，注意不是物理地址。
pte_t *pgdir_walk(pde_t *pgdir, const void *va, int create);
```

# 4 JOS内存组织
由于 JOS 只用了一个页目录，不像现代操作系统那样每个都有自己的页目录，所以整个系统的线性地址只有 4GB。JOS中内存组织如下图所示：

![JOS内存组织](https://upload-images.jianshu.io/upload_images/286774-70ab857ebcd75702.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


在lab2的内存映射中，我们主要映射了3个区域，第一个是 [UPAGES, UPAGES+PTSIZE)映射到页表存储的物理地址 [pages, pages+4M) 。第二个是 [KSTACKTOP-KSTKSIZE, KSTACKTOP) 映射到 [bootstack, bootstack+32KB)处。第三个则是映射整个内核的虚拟空间[KERNBASE, 2*32-KERNBASE) 到 物理地址 [0, 256M)。

映射完成后，会将cr3寄存器的内容从entry_pgdir替换为kern_pgdir，完成新的页目录地址装载，以保证新的映射生效。
