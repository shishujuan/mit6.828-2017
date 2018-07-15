# Exercize 1

完成 kern/kmap.c 文件中的下面几个函数，可以使用 `check_page_free_list()和check_page_alloc()`函数检查内存分配是否成功：

```
boot_alloc()
mem_init() (only up to the call to check_page_free_list(1))
page_init()
page_alloc()
page_free()
```

### boot_alloc

其中boot_alloc只在JOS建立虚拟内存系统的时候使用，后续的内存分配用的是page_alloc()函数。需要注意的是这里只是将可以使用的空闲内存地址返回，并没有真正的操作物理内存。

```
static void *
boot_alloc(uint32_t n)
{
    static char *nextfree;
    char *result;

    if (!nextfree) {
        extern char end[];
        nextfree = ROUNDUP((char *) end, PGSIZE);
    }   
   
    cprintf("boot_alloc, nextfree:%x\n", nextfree);
    result = nextfree;
    if (n != 0) {
        nextfree = ROUNDUP(nextfree + n, PGSIZE);
    }   

    return result;
}
```

### mem_init

注释掉那行panic代码，加入pages的初始化代码:

```
// panic("mem_init: This function is not finished\n");
pages = (struct PageInfo *)boot_alloc(sizeof(struct PageInfo) * npages);
```

### page_alloc
从空闲链表取第一个，并更新链表头指向下一个空闲位置，如果指定了alloc_flag，则将PageInfo结构对应的那4KB内存区域清零(用page2kva(page)可以得到对应页面的虚拟地址):

```
struct PageInfo *
page_alloc(int alloc_flags)
{
    if (page_free_list) {
        struct PageInfo *result = page_free_list;
        page_free_list = page_free_list->pp_link;
        if (alloc_flags & ALLOC_ZERO) {
            memset(page2kva(result), 0, PGSIZE);
        }
        return result;
    }
    return NULL;
}
```

### page_free
释放对应页面，将该页面对应的PageInfo项加入page_free_list链表头部。

```
void
page_free(struct PageInfo *pp)
{
    assert(pp->pp_ref == 0 && pp->pp_link == NULL); 
    pp->pp_link = page_free_list;
    page_free_list = pp; 
}
```

### page_init
初始化pages，设置空闲链表，一旦初始化好页面后，后续的页面分配用 page_alloc，不要再用boot_alloc。

```
void
page_init(void)
{
    // 1）第0页不用，留给中断描述符表
    // 2）第1-159页可以使用，加入空闲链表（npages_basemem为160，即640K以下内存)
    // 3）640K-1M空间保留给BIOS和显存，不能加入空闲链表
    // 4）1M以上空间中除去kernel已经占用的页，其他都可以使用
    size_t i;
    for (i = 1; i < npages_basemem; i++) {
        pages[i].pp_ref = 0;
        pages[i].pp_link = page_free_list;
        page_free_list = &pages[i];
    }

    char *nextfree = boot_alloc(0);
    size_t kern_end_page = PGNUM(PADDR(nextfree));
    cprintf("kern end pages:%d\n", kern_end_page);

    for (i = kern_end_page; i < npages; i++) {
        pages[i].pp_ref = 0;
        pages[i].pp_link = page_free_list;
        page_free_list = &pages[i];
    }
}
```

# Exercize 2
熟悉80386手册的第5，6章，熟悉分页和分段机制以及基于页的保护机制，理论篇已经总结。


# Exercize 3

熟悉qemu的调试命令，使用 `CTRL+a+c` 进入monitor模式，可以输入命令 `info pg`查看页表项，使用`info mem`查看内存概要，使用 `xp /Nx paddr` 查看物理地址处的内容，与 gdb 的 `p /Nx vaddr` 可以验证对应地址的数据是否一致。


# Exercize 4

前面我们只是完成了页表管理的结构如空闲链表page_free_list和页表数组pages的初始化，现在需要加入页表管理的函数。

### pgdir_walk
根据虚拟地址va找到对应的页表项地址。如果指定了create标志，则如果物理页不存在的时候分配新的页，并设置页目录项的值为新分配页的物理地址。

```
pte_t *
pgdir_walk(pde_t *pgdir, const void *va, int create)
{
    int pde_index = PDX(va);
    int pte_index = PTX(va);
    pde_t *pde = &pgdir[pde_index];
    if (!(*pde & PTE_P)) {
        if (create) {
            struct PageInfo *page = page_alloc(ALLOC_ZERO);
            if (!page) return NULL;

            page->pp_ref++;
            *pde = page2pa(page) | PTE_P | PTE_U | PTE_W;
        } else {
            return NULL;
        }   
    }   

    pte_t *p = (pte_t *) KADDR(PTE_ADDR(*pde));
    return &p[pte_index];
}
```

### boot_map_region

映射虚拟地址va到物理地址pa，映射大小为size，所做操作就是找到对应的页表项地址，设置页表项的值为物理地址pa(pa是4KB对齐的，对应该页的首地址)。用到上一个函数pgdir_walk找虚拟地址对应的页表项地址。

```
static void
boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm)
{
    int pages = PGNUM(size);
    for (int i = 0; i < pages; i++) {
        pte_t *pte = pgdir_walk(pgdir, (void *)va, 1);
        if (!pte) {
            panic("boot_map_region panic: out of memory");
        }
        *pte = pa | perm | PTE_P;
        va += PGSIZE, pa += PGSIZE;
    }
}
```

### page_lookup
查找虚拟地址va对应的页表项，并返回页表项对应的PageInfo结构。

```
struct PageInfo *
page_lookup(pde_t *pgdir, void *va, pte_t **pte_store)
{
    pte_t *pte = pgdir_walk(pgdir, va, 0);
    if (!pte || !(*pte & PTE_P)) {
        return NULL;
    }

    if (pte_store) {
        *pte_store = pte;
    }

    return pa2page(PTE_ADDR(*pte));
}
```

### page_remove
从页表中移除虚拟地址va对应的物理页映射。需要将PageInfo的引用pp_ref减1，并设置对应页表项的值为0，最后调用tlb_invalidate使tlb中该页缓存失效。

```
void
page_remove(pde_t *pgdir, void *va)
{
    pte_t *pte;
    struct PageInfo *page = page_lookup(pgdir, va, &pte);
    if (!page || !(*pte & PTE_P)) {
        return;
    }
    *pte = 0;
    page_decref(page);
    tlb_invalidate(pgdir, va);
}
```

### page_insert
映射虚拟地址va到pp对应的物理页。如果之前该虚拟地址已经存在映射，则要先移除原来的映射。注意pp_ref++要在page_remove之前执行，不然在page_remove会导致pp_ref减到0从而page_free该页面，该页面后续会被重新分配使用而报错。

```
int
page_insert(pde_t *pgdir, struct PageInfo *pp, void *va, int perm)
{
    pte_t *pte = pgdir_walk(pgdir, va, 1);
    if (!pte) {
        return -E_NO_MEM;
    }

    pp->pp_ref++;
    if (*pte & PTE_P) {
        page_remove(pgdir, va);
    }

    *pte = page2pa(pp) | perm | PTE_P;
    return 0;
}
```

# Exercize 5

映射 UPAGES, KSTACK, KERNBASE等虚拟地址空间到物理内存。注意一点就是KSTACK映射的bootstack是在内核里面分配好的，所以它在物理内存地址要在 UPAGES 映射的物理地址pages 之前的一段区域。

```
boot_map_region(kern_pgdir, UPAGES, PTSIZE, PADDR(pages), PTE_U);
boot_map_region(kern_pgdir, KSTACKTOP-KSTKSIZE, KSTKSIZE, PADDR(bootstack), PTE_W);
// -KERNBASE转换为uint类型正好是 2**32 - KERNBASE
boot_map_region(kern_pgdir, KERNBASE, -KERNBASE, 0, PTE_W);
```

# Questions
## Question 1

假定下面代码运行正确，那么变量x的类型应该是 uintptr_t 还是 physaddr_t?

```
	mystery_t x;
	char* value = return_a_pointer();
	*value = 10;
	x = (mystery_t) value;
```
在代码中我们操作的都是虚拟地址，因此x类型应该是 uintptr_t。

## Question 2
哪些页目录已经被填充好，它们的地址映射是怎么样的？基本就是 Exercize 5 中做的地址映射。


## Question 3
我们将用户和内核环境放在了同一个地址空间，如何保证用户程序不能读取内核的内存？
内核空间内存的页表项的perm没有设置PTE_U，需要CPL为0-2才可以访问。而用户程序的CPL为3，因为权限不够用户程序读取内核内存时会报错。


## Question 4
JOS最大可以支持多大的物理内存，为什么？
2GB，因为 UPAGES 大小最大为4MB，而每个PageInfo大小为8B，所以可以最多可以存储512K个PageInfo结构体，而每个PageInfo对应4KB内存，所以最多 512K*4K = 2G内存。

## Quesiton 5
如果我们真有这么多物理内存，用于管理内存额外消耗的内存空间有多大？
如果有2GB内存，则物理页有512K个，每个PageInfo结构占用8字节，则一共是4MB。页目录需要 `512*8=4KB`，而页表包括512K个页表项，每项4字节共需要`512K*4=2MB`存储，所以额外消耗的内存为 `6MB + 4KB`。

## Question 6
EIP什么时候开始从低地址空间(1M多一点)的地方跳转到高地址（KERNBASE之上）运行的，为什么这一步是正常的而且是必要的？

从 kern/entry.S 中的 `jmp     *%eax`语句之后就开始跳转到高地址运行了。因为在entry.S中我们的cr3加载的是entry_pgdir，它将虚拟地址 [0, 4M)和[KERNBASE, KERNBASE+4M)都映射到了物理地址 [0, 4M)，所以能保证正常运行。

而在我们新的kern_pgdir加载后，并没有映射低位的虚拟地址 [0, 4M)，所以这一步跳转是必要的。

# Challenge
其他几个比较难，实现下showmappings, setperm，showvm方便调试。

```
void
pte_print(pte_t *pte)
{
    char perm_w = (*pte & PTE_W) ? 'W' : '-';
    char perm_u = (*pte & PTE_U) ? 'U' : '-';
    cprintf("perm: P%c%c\n", perm_w, perm_u);
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
    if (argc < 3) {
        cprintf("Usage: showmappings begin_addr end_addr\n");
        return 0;
    }

    uint32_t begin = strtol(argv[1], NULL, 16);
    uint32_t end = strtol(argv[2], NULL, 16);
    if (begin > end) {
        cprintf("params error: begin > end\n");
        return 0;
    }
    cprintf("begin: %x, end: %x\n", begin, end);

    for (; begin <= end; begin += PGSIZE) {
        pte_t *pte = pgdir_walk(kern_pgdir, (void *) begin, 0);
        if (!pte || !(*pte & PTE_P)) {
            cprintf("va: %08x not mapped\n", begin);
        } else {
            cprintf("va: %08x, pa: %08x, ", begin, PTE_ADDR(*pte));
            pte_print(pte);
        }
    }
    return 0;
}

int
mon_setperm(int argc, char **argv, struct Trapframe *tf)
{
    if (argc < 4) {
        cprintf("Usage: setperm addr [0|1] [P|W|U]\n");
        return 0;
    }
    uint32_t addr = strtol(argv[1], NULL, 16);
    pte_t *pte = pgdir_walk(kern_pgdir, (void *)addr, 0);
    if (!pte || !(*pte & PTE_P)) {
        cprintf("va: %08x not mapped\n", addr);
    } else {
        cprintf("%x before set, ", addr);
        pte_print(pte);

        uint32_t perm = 0;
        char action = argv[2][0];
        char perm_param = argv[3][0];
        switch(perm_param) {
            case 'P':
                perm = PTE_P;
                break;
            case 'W':
                perm = PTE_W;
                break;
            case 'U':
                perm = PTE_U;
                break;
        }

        cprintf("perm_param:%c, action:%c, perm:%d\n", perm_param, action, perm);
        if (action == '0') {
            *pte = *pte & ~perm;
        } else {
            cprintf("set perm %d\n", perm);
            *pte = *pte | perm;
        }

        cprintf("%x after set, ", addr);
        pte_print(pte);
    }

    return 0;
}

int
mon_showvm(int argc, char **argv, struct Trapframe *tf)
{
    if (argc < 3) {
        cprintf("Usage: showvm addr n\n");
        return 0;
    }

    void** addr = (void**) strtol(argv[1], NULL, 16);
    uint32_t n = strtol(argv[2], NULL, 10);
    int i;
    for (i = 0; i < n; i++) {
        cprintf("vm at %x is %x\n", addr+i, addr[i]);
    }
    return 0;
}
```

# 参考资料
* [https://pdos.csail.mit.edu/6.828/2017/labs/lab2/](https://pdos.csail.mit.edu/6.828/2017/labs/lab2/)
* [https://pdos.csail.mit.edu/6.828/2017/lec/](https://pdos.csail.mit.edu/6.828/2017/lec/)
* [https://github.com/Clann24/jos/tree/master/lab2](https://github.com/Clann24/jos/tree/master/lab2)
