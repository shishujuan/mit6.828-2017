> mit6.828的JOS系统启动分为两部分，Boot Loader和kern。BIOS加载Boot Loader程序，在完成它的一系列初始化后便把控制权交给Boot Loader程序，在 我们的 JOS 实验中，我们的 Boot Loader 程序会在编译成可执行代码后被放在模拟硬盘的第一个扇区。实验代码中有Kern和Boot两个可执行文件，其中 Kernel 是即将被 Boot Loader 程序装入内存的内核程序，而 Boot 便是 Boot Loader 本身 的可执行程序。

# 1 系统启动流程
实验环境用的qemu，模拟了BIOS加载引导程序（Boot Loader）到内存中，然后启动系统。现代PC的BIOS程序通常都固化在EPROM芯片中，这是一种可擦除可编程的非易失性芯片。CPU硬件逻辑设计为在加电瞬间强行将CS值置为0XF000，IP为0XFFF0(模拟器里面的CPU初始指令设置是这么设置的，最终的地址是0xFFFF0，而在80386之后的CPU中这个地址是0xFFFFFFF0)，这样实模式下CS:IP就指向0XFFFF0这个位置(段地址 << 4 + 偏移地址)，这个位置正是BIOS程序的入口地址。BIOS 的作用是完成机器自检，对系统进行初始化，比如像激活 显卡、检查内存的总量，设置中断向量等。在进行完这些初始化后，BIOS 便将Boot Loader从一个合适的位置装载到内存0x7C00处，这些位置可以是软盘、硬盘、CD-ROM 或者是网络，在这之后，BIOS 便会将控制权交给操作系统。

有一个问题就是，BIOS程序是固化到它自己的芯片中的，那CPU是如何在初始的情况下就能运行BIOS程序的。这是CPU自身决定的，CPU的reset vector设置为了前面提到的0XFFFF0，每次PC复位，则CPU就会从该位置执行，这正好是BIOS程序的起始位置。注意，此时内核还没有进行内存初始化，CPU是怎么读取BIOS ROM的？x86对BIOS ROM进行统一编址，此时CPU使用通用的读指令从BIOS ROM(不是内存)里面读取指令执行(CPU读取指令通常先发送到北桥芯片，而北桥芯片根据内存地址映射来决定该指令地址是发往哪里。BIOS ROM内存映射在低端地址处，于是CPU访问0XFFFF0这个地址时北桥芯片会将读取指令请求发送到BIOS ROM，QEMU有自己的BIOS程序，它会被加载到模拟的地址空间0xf0000到0xfffff这段物理内存，从而可以让虚拟机的CPU执行对应位置的BIOS指令)。可以看到BIOS程序首先执行了一个跳转指令 `ljmp   $0xf000,$0xe05b` ，这是因为BIOS在内存中的结束范围为 0x100000，而 0xFFFF0 到 0x100000 只有16个字节，想想这么一点内存也存放不了几条指令，因此先跳转到一个第一点的地方执行。

另外一个问题是，BIOS将Boot Loader加载到内存0x7C00处，加载完成后将控制权交给Boot Loader，Boot Loader然后加载操作系统的内核到内存中，那BIOS是如何判断从哪里加载Boot Loader呢？BIOS将所检查磁盘的第一个扇区(512B)载入内存，放在 0x0000:0x7c00 处， 如果该扇区的最后两个字节是“55 AA”，那么这就是一个引导扇区，这个磁盘也就是一块可引导盘。通常这个大小为 512B 的程序就称为引导程序(bootloader)。如果最后两个字节不是“55 aa”，那么 BIOS 就检查下一个磁盘驱动器，这个检查顺序也是可以在BIOS中设置的，BIOS设置存储在CMOS中。

PC的物理地址空间的布局如下所示，低1M空间是BIOS设置好的。其中包括中断向量，BIOS数据，显示内存等（如0x0-0x000003ff存储中断向量）。此时，操作系统还没有加载，那么BIOS加载Boot Loader是通过什么方式呢？其实就是通过BIOS中断来实现。要读取磁盘扇区，我们需要使用 BIOS 的 0x13h(第20) 号中断，0x13h 号中断会将几个寄存器的值作为其参数将指定的磁盘扇区读取到内存中。

```

+------------------+  <- 0xFFFFFFFF (4GB)
|      32-bit      |
|  memory mapped   |
|     devices      |
|                  |
/\/\/\/\/\/\/\/\/\/\

/\/\/\/\/\/\/\/\/\/\
|                  |
|      Unused      |
|                  |
+------------------+  <- depends on amount of RAM
|                  |
|                  |
| Extended Memory  |
|                  |
|                  |
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


而加载的地址0x7C00是历史原因，IBM最早的个人电脑IBM PC 5150用的是Intel最早的个人电脑芯片8088，当时，搭配的操作系统是86-DOS。这个操作系统需要的内存最少是32KB。内存地址从0x0000开始编号，32KB的内存就是0x0000～0x7FFF。
8088芯片本身需要占用0x0000～0x03FF，用来保存各种中断向量的储存位置。所以，内存只剩下0x0400～0x7FFF可以使用。为了把尽量多的连续内存留给操作系统，Boot Loader就被放到了内存地址的尾部。由于Boot Loader所在的这个扇区是512字节，另外Boot Loader数据和栈需要预留512字节。所以，Boot Loader加载位置是0x7c00，而且因为操作系统加载完成后Boot Loader不需要再使用，这部分内存之后操作系统是可以重复利用的。

```
 0x7FFF - 512 - 512 + 1 = 0x7C00 
```

# 2 引导程序
引导程序Boot Loader负责加载操作系统内核Kern，它被BIOS加载到0x7c00-0x7dff中。“boot block is 406 bytes (max 510)”这句话表示存放在第一个扇区的Boot Loader 可执行程序的大小不能超过 510 个字节，由于磁盘的一个扇区的大小为 512 字节， 这样便保证了 bootloader 仅仅只占据磁盘的第一个扇区。

实验中编译好的Boot Loader位于`obj/boot/boot`，大小刚好是512字节。我们可以确认下最后两个字节确实是`55 aa`。

```
# hexdump obj/boot/boot
0000000 fa fc 31 c0 8e d8 8e c0 8e d0 e4 64 a8 02 75 fa
0000010 b0 d1 e6 64 e4 64 a8 02 75 fa b0 df e6 60 0f 01
.......
00001f0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 aa
```

JOS 的引导由`boot/boot.S`的汇编程序和`boot/main.c`的C程序两个程序完成。boot.S 主要是将处理器从实模式转换到 32 位的保护模式，因为只有在保护模式中我们才能访问到物理内存高于 1MB 的空间。main.c 的主要作用是将内核的可执行代码从硬盘镜像中读入到内存中， 具体的方式是运用 x86 专门的 I/O 指令读取。

boot.S 会初始化寄存器，设置代码段选择子和数据段选择子的值（保护模式会用到），打开A20地址线。接着`lgdt gdtdesc`加载全局描述符表（这里一共两个描述符表，分别用于代码段和数据段选择子），全局描述符表就是一个类似数组的结构而已。设置寄存器CR0的最低位值为1打开保护模式，然后跳转到 `PROT_MODE_CSEG: protcseg` 执行。从全局描述符表中可以得知，代码段选择子 PROT_MODE_CSEG 的段基址为 0，其中偏移地址是 $protcseg，$protcseg 实际上代表 的是接下来指令的链接地址，也就是可执行程序在内存中的虚拟地址(VMA)，只是刚好在这里编译生成的可执行程序 boot 的加载地址(LMA)与链接地址是一致的，于是 $protcseg 就相当于指令在内存中实际存放位置的物理地址，所以这个长跳转可以成功的跳转到下一条指令的位置。

进入保护模式后，程序在重新对段寄存器进行了初始化并且赋值了堆栈指针后便调用 bootmain 函数，在“call bootmain”之后便是一个无限循环的跳转指令，这个无限循环没有太大意义，只是为了让整个代码更有完整性。之后的代码则是定义了 GDT 表，一共3个表项，第一个为NULL,接着为代码段选择子和数据段选择子，其中代码中的 STA_X(0x8) 表示可执行（仅限于可执行段），STA_R(0x2) 表示可读（仅限于可执行段），STA_W(0x2) 为可写（仅限于非可执行段）。

# 3 实模式和保护模式
实模式采用 16 位寻址模式，在该模式中，最大寻址空间为 1MB，最大分段为 64KB。
由于处理器的设计需要考虑到兼容问题，8086 处理器地址总线扩展到 20 位，但CPU的ALU宽度(数据总线)却只有 16 位，也就是说直接参与运算的数值都是 16 位的。为支持 1MB 寻址空间，8086 处理器在实模式下引入了分段方法。在处理器中设置了四个 16 位的段寄存器:CS、DS、SS、ES，对 应于地址总线中的高 16 位。寻址时，采用以下公式计算实际访问的物理内存地址，这样，便实现了 16 位内存地址到 20 位物理地址的转换。

```
实际物理地址 = (段寄存器 << 4) + 偏移地址 
```

在保护模式下，段式寻址可用 xxxx:yyyyyyyy 表示。其中 xxxx 表示索引，也就是段选
择子，是 16 位的。yyyyyyyy 是偏移量，是 32 位的分段机制是利用一个称作段选择子的偏移量到全局描述符表中找到需要的段描述符，而这个段描述符中就存放着真正的段的物理首地址，然后再加上偏移地址量便得到了最后的物理地址。需要指出的是，在 32 位平台上，段物理首地址和偏移址都是 32 位的，实际物理地址的计算不再需要将段首地址左移 4 位了，直接相加即可，如果发生溢出的情况，则将溢出位舍弃。

保护模式下会有一个寄存器GDTR(Global Descriptor Table Register)用于存储全局描述符表的物理地址和长度，这样可以由段选择子 xxxx 查询全局描述符表(全局描述符表存储类似数组），得到对应段描述符，一个 64 位的段描述符包含了段的物理首地址、段的界限以及段的属性。在描述符中，段基址占 32 位，段限长占 20 位，属性占 12 位，详细字段说明参见 [GDT](https://wiki.osdev.org/GDT)。段描述符的基地址加上偏移 yyyyyyyy 即可得到物理地址(严格来讲，此时还是将逻辑地址转换为了线性地址，如果设置了寄存器CR3的最低位为1开启了分页后，会再将这个地址再次通过MMU转换为真正的物理地址)。

段描述符的定义如下：

```
 BYTE7          BYTE6 BYTE5   BYTE4 BYTE3 BYTE2    BYTE1 BYTE0   
 段基址31...24     属性           段基址 23...0        段限长 15...0
```


# 4 ELF 文件结构
在Boot Loader那节中我们看到了一些如 gdtdesc, progcseg 这样的地址标识符，那么这些地址是什么地址呢？它们与内存中的物理地址区别是什么呢？这一节来探讨下这个问题。

在说明链接地址和加载地址区别之前，我们先来看下 ELF 文件格式。ELF 文件可以分为这样几个部分: ELF 文件头、程序头表(program header table)、节头表(section header table)和文件内容。而其中文件内容部分又可以分为这样的几个节:.text 节、.rodata 节、.stab 节、.stabstr 节、.data 节、.bss 节、.comment 节。

```
						+------------------+ 
						|    ELF 文件头     |
						+------------------+  
						|    程序头表       |
						+------------------+  
						|    .text 节      |
						+------------------+                  
						|    .rodata 节    |
						+------------------+   
						|    .stab 节      |
						+------------------+        
						|    .stabstr 节   |
						+------------------+                                 
						|    .data 节      |
						+------------------+  
						|    .bss 节       |
						+------------------+  
						|    .comment 节   |
						+------------------+      
						|    节头表         |
						+------------------+                                                                                                                                                   
```


ELF 文件头结构如下，其中e_entry 是可执行程序的入口地址，即从内存的这个位置开始执行，在这里入口地址是虚拟地址 VMA ，也就是链接地址; e_phoff 和 e_phnum 可以用来找到所有的程序头表项，e_phoff 是程序头表的第一项相对于 ELF 文件的开始位置的偏移，而 e_phnum 则是表项的个数;同理 e_ shoff 和 e_ shnum 可以用来找到所有的节头表项。

```
// ELF 文件头
struct Elf {
	uint32_t e_magic; // 标识是否是ELF文件
	uint8_t e_elf[12]; // 魔数和相关信息 
	uint16_t e_type; // 文件类型
	uint16_t e_machine; 
	uint16_t e_version; // 版本信息
	uint32_t e_entry; // 程序入口点
	uint32_t e_phoff; // 程序头表偏移值
	uint32_t e_shoff; // 节头表偏移值
	uint32_t e_flags; 
	uint16_t e_ehsize;  // 文件头长度
	uint16_t e_phentsize; // 程序头部长度 
	uint16_t e_phnum; // 程序头部个数 
	uint16_t e_shentsize; // 节头部长度 
	uint16_t e_shnum; // 节头部个数 
	uint16_t e_shstrndx; // 节头部字符索引
};
```

程序头表中每个表项就代表一个段，这里的段是不同于之前节的概念，几个节可能会包含在同一个段里。程序头表项的数据结构如下所示:

```
struct Proghdr { 
	uint32_t p_type; // 段类型
	uint32_t p_align; // 段在内存中的对齐标志
	uint32_t p_offset; // 段位置相对于文件开始处的偏移量
	uint32_t p_va; // 段的虚拟地址
	uint32_t p_pa; // 段的物理地址
	uint32_t p_filesz; // 段在文件中长度
	uint32_t p_memsz; // 段在内存中的长度 
	uint32_t p_flags; // 段标志
}
```

这里比较重要的几个成员是 p_offset、p_va、p_filesz 和 p_memsz。其中通过 p_offset 可以找到该段在磁盘中的位置，通过 p_va 可以知道应该把这个段放到内存的哪个位置，而之所以需要 p_filesz 和 p_memsz 这两个长度是因为 .bss 这种节在硬盘没有存储空间而在内存中需要为其分配空间。

通过 ELF 文件头与程序头表项找到文件的第 i 段地址的方法如下：

```
第 i 段程序头表表项位置 = 文件起始位置 + 程序头表偏移e_phoff + i * 程序头表项字节数 
第 i 段地址就是第i个程序头表表项的 p_offset 值。
```

而 ELF 文件还有节点表，通过 ELF 文件头和节头表可以找到对应节的位置，方式与找到第i段的位置类似。ELF 的文件内容主要的几个节的说明如下（一些特殊节如eh_frame用于展示栈的调用帧信息，这里不做说明）：

```
// 节头信息
struct Secthdr { 
	uint32_t sh_name;// 节名称
	uint32_t sh_type; // 节类型
	uint32_t sh_flags; // 节标志
	uint32_t sh_addr; // 内存中的虚拟地址
	uint32_t sh_offset; // 相对于文件首部的偏移
	uint32_t sh_size; // 节大小
	uint32_t sh_link; // 与其他节关系
	uint32_t sh_info; // 其他信息
	uint32_t sh_addralign; // 字节对齐标志 
	uint32_t sh_entsize; // 表项大小
};

// 各个节说明
.text 节: 可执行指令的部分。
.rodata 节: 只读全局变量部分。
.stab 节: 符号表部分，在程序报错时可以提供错误信息。
.stabstr 节: 符号表字符串部分。
.data 节: 可读可写的全局变量部分。
.bss 节: 未初始化全局变量部分，这一部分不会在磁盘有存储空间，但在内存中会分配空间。
.comment 节:注释部分，这一部分不会被加载到内存。
```

可以使用 objdump 命令查看 ELF 文件的节信息，如boot文件有下面5个节，而kernel文件则有上面提到的7个节，而且可以看到kernel中.bss和.comment的在文件的偏移 `File off` 是一样的，说明.bss不占用磁盘空间，仅仅记录了它的长度。

```
# objdump -h obj/boot/boot
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         0000017e  00007c00  00007c00  00000054  2**2
                  CONTENTS, ALLOC, LOAD, CODE
  1 .eh_frame     000000cc  00007d80  00007d80  000001d4  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .stab         000006d8  00000000  00000000  000002a0  2**2
                  CONTENTS, READONLY, DEBUGGING
  3 .stabstr      000007df  00000000  00000000  00000978  2**0
                  CONTENTS, READONLY, DEBUGGING
  4 .comment      00000011  00000000  00000000  00001157  2**0
                  CONTENTS, READONLY

# objdump -h obj/kern/kernel
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         00001917  f0100000  00100000  00001000  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rodata       00000714  f0101920  00101920  00002920  2**5
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .stab         00003889  f0102034  00102034  00003034  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .stabstr      000018af  f01058bd  001058bd  000068bd  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 .data         0000a300  f0108000  00108000  00009000  2**12
                  CONTENTS, ALLOC, LOAD, DATA
  5 .bss          00000644  f0112300  00112300  00013300  2**5
                  ALLOC
  6 .comment      0000002b  00000000  00000000  00013300  2**0
                  CONTENTS, READONLY
```

#5 链接地址和加载地址
好了，是时候来说下链接地址和加载地址的区别了。ELF文件的节的链接地址实际上就是它期望开始执行的内存地址，链接器可用多种方式编码二进制可执行文件中的链接地址，编译器在编译的时候会认定程序将会连续的存放在从链接地址起始处开始的内存空间。**程序的链接地址实际上就是链接器对代码中的变量、函数等符号进行一个地址编排，赋予这些抽象的符号一个地址，然后在程序中通过地址访问相应变量和函数。要清楚的一点是，在ELF文件中的汇编代码或者机器指令中，符号已经不复存在，一切引用都是地址！**使用ld等链接程序时通过`-Ttext xxxx` 和 `-Tdata yyyy` 指定代码段/数据段的链接地址。运行期间，代码指令和数据变量的地址都在相对-T指定的基址的某个偏移量处。这个地址实际上就是链接地址（VMA）。

而加载地址则是可执行程序在物理内存中真正存放的位置，而在 JOS 中，Boot Loader 是被 BIOS 装载到内存的，而这里 BIOS 实际上规定 Boot Loader 是要存放在物理内存的 0x7c00 处，于是不论程序的链接地址(VMA)怎么改变，它的加载地址(LMA)都不会改变。

在JOS中，Boot Loader的链接地址在 `boot/Makefrag`里面定义的，为0x7C00。该文件的另外几个命令是生成 `obj/boot/`目录下面的几个文件的，该目录下 `boot.out` 是由 `boot/boot.S` 和 `boot/main.c`编译链接后生成的 ELF 可执行文件，而 `boot.asm` 是从可执行文件 `boot.out` 反编译的包含源码的汇编文件，而最后通过 objcopy 拷贝 boot.out中的 .text 代码节生成最终的二进制引导文件 boot (380个字节)，最后通过 sign.pl这个perl脚本填充 boot 文件到512字节（最后两个字节设置为 55 aa，代表这是一个引导扇区）。最终生成的镜像文件在 `obj/kern/kernel.img`，它大小为5120000字节，即10000个扇区大小。第一个扇区写入的是 `obj/boot/boot`，第二个扇区开始写入的是 `obj/kern/kernel`。


```
# boot 相关文件生成代码
$(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 -o $@.out $^
$(V)$(OBJDUMP) -S $@.out >$@.asm
$(V)$(OBJCOPY) -S -O binary -j .text $@.out $@
$(V)perl boot/sign.pl $(OBJDIR)/boot/boot
	
# kernel.img 创建代码
$(V)dd if=/dev/zero of=$(OBJDIR)/kern/kernel.img~ count=10000 2>/dev/null
$(V)dd if=$(OBJDIR)/boot/boot of=$(OBJDIR)/kern/kernel.img~ conv=notrunc 2>/dev/null
$(V)dd if=$(OBJDIR)/kern/kernel of=$(OBJDIR)/kern/kernel.img~ seek=1 conv=notrunc 2>/dev/null
$(V)mv $(OBJDIR)/kern/kernel.img~ $(OBJDIR)/kern/kernel.img
```

Boot Loader的链接地址和加载地址是一样的，都是0x7C00。而Kernel的链接地址和加载地址却是不一样的。链接地址是 `0xF0100000`，加载地址是`0x00100000`，也就是说Kernel加载到了内存中的 0x00100000 这个低地址处，但是却期望在一个高地址 0xF0100000 执行，为什么要这么做呢？这是因为我们的内核通常期望链接和运行在一个高的虚拟地址，以便把低位的虚拟地址空间让给用户程序使用。但是，以前的机器通常没有 0xF0100000 这么大的物理内存，因此需要通过处理器的内存管理硬件来将 0xF0100000 映射到 0x00100000，我们在下一节会看到这个机制是怎么实现的。

查看`obj/boot/boot.asm`可以看到确实最终的二进制代码文件 boot 的链接地址为 0x7C00，代码从这个地址开始依次存放。而执行时，我们前面提到过是BIOS将Boot Loader代码加载到内存中 0x7C00 的位置，这里恰好 VMA 和 LMA是一样的。如果我们把`Makefrag`中的 0x7C00 改成 0x7C10，会在哪条指令报错呢？答案是在 `jmp 0008:7c42` 后报错。这是因为我们链接地址改成了 0x7C10 ，而实际加载地址还是 0x7C00，这样在执行完 `ljmp 0008:7c42` 这条指令时，此时要去寻找 0x7c42 处的指令`movw ax, 10`运行，而实际上这个地址处并不是合法的指令，因为加载地址并没有变，`movw ax, 10`还是在地址 0x7c32 处，因此此时会报错。


# 6 加载内核(Kernel）
BIOS负责加载Boot Loader，而Boot Loader 负责加载内核。编译好的内核位于 `obj/kern/kernel`，当然最终要写入到镜像文件 `obj/kern/kernel.img`中。从 `kern/kernel.ld` 中可以看到内核的链接地址设置的是 `0xF0100000`，而加载地址设置的是 `0x00100000`。 `boot/main.c` 中的 `bootmain()` 函数负责加载内核，采用的是分段加载方法。使用命令 `readelf -l obj/kern/kernel` 可以看到内核分段信息，kernel需要加载的有2段(LOAD标识)，以 4K (0x1000) 对齐。我们可以看到加载kernel时，是以扇区为单位读取并加载的。首先会将文件的前 4K 数据即ELF头和程序头表（注意是从扇区1开始读取，因为扇区0是bootloader）加载到物理地址 0x10000 处（注意这个不是kernel加载的地址 0x00100000，少个0），这样ELF文件头和程序头表都能读取了，接着就可以根据程序头表加载程序段到对应物理地址了。

```
# readelf -l obj/kern/kernel

Elf file type is EXEC (Executable file)
Entry point 0x10000c
There are 3 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x001000 0xf0100000 0x00100000 0x0716c 0x0716c R E 0x1000
  LOAD           0x009000 0xf0108000 0x00108000 0x0a300 0x0a944 RW  0x1000
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10

 Section to Segment mapping:
  Segment Sections...
   00     .text .rodata .stab .stabstr 
   01     .data .bss 
   02     

```

可以看到 kernel 可执行文件的第一段包含了 ELF 文件的.test 节、.rodata 节、.stab
.data节，而文件的第二段包含了.data 节以及在硬盘上不占用空间但在内存中占据 0x644 字节的.bss 节，这样 Boot Loader 便会在从硬盘读入第二段的同时为 .bss 节在内存中分配空间。另外，.comment 节没有被包含在任意一段，这表明它没有被装入内存。

另外需要注意的是，硬盘中的每一扇区加载到内存的时候都需要按 512 字节对齐。readsec() 函数用于读取一个扇区的数据，而waitdisk() 函数的作用是等待直到硬盘准备好可以让程序读取数据。

```
void
bootmain(void)
{
	struct Proghdr *ph, *eph;

	// 读取前4K数据，包括ELF头部和程序头表到物理地址0处
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);

	// 判断是不是ELF文件
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;

	// 加载程序段
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
		// p_pa 是加载地址，也就是物理地址，p_memsz是段在内存中长度，p_offset段在文件中的偏移。
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);

	// 转到kernel入口点执行，并且不再返回。
	((void (*)(void)) (ELFHDR->e_entry))();
}
```

bootmain() 加载kernel完成后，跳转到kernel的入口 e_entry（物理地址0x10000c处）执行。**需要牢记的是，在代码中的地址我们称之为虚拟地址或链接地址，在开启了保护模式后(设置cr0的低位为1)，会经过全局描述符表项来生成线性地址，如果开启了分页(设置cr3的低位为1)，则会将线性地址经过分页转换为物理地址，否则，线性地址就等于物理地址。**

因此，bootmain() 函数里面最后跳转的是 e_entry 的物理地址值 0x0010000c，而不是链接地址值 0xf010000c。因为 kernel 代码本身就是加载在 0x0010000c，而我们的描述符表项里面存的代码段基地址是0，所以只有在 0x0010000c 处才能找到可执行指令，此时在 0xf010000c处我们还没有做好映射。

注意到kernel的 e_entry 的值其实就是汇编文件 `kern/entry.S` 中的 `_start` 值，所以这个值必须是指向物理地址才行，因为我们还没有做好高地址的映射。设置好了入口地址 _start 后，`kernel/entry.S` 设置好cr3寄存器的值为页目录的物理地址，然后设置cr0开启分页，最后跳转到 relocated 执行。relocated 是类似0xf01xxxxx之类的连接地址，为什么可以执行了呢？这是因为我们已经开启分页，而且在 `entrypgdir.c` 中已经设置好高位地址的页目录项。在 relocated 中，先初始化 栈帧指针寄存器 ebp，用于追溯函数调用流程，然后设置 堆栈寄存器 esp 的值为内核栈栈顶，堆栈大小为32KB。（留个问题，如果将kern/entry.S中的 jmp *%eax 改成 call *%eax，会报triple fault，为什么呢？想想call和jmp的区别以及entry_pgdir在低地址和高地址的页表的映射权限有什么区别，报错的地址是 0x7be8，此时的esp是0x7bec，我想你应该知道原因了）。


```
.globl		_start
_start = RELOC(entry)

.globl entry
entry:
	movw	$0x1234,0x472			# warm boot

	# entry_pgdir在entrypgdir.c中定义，这段代码作用
	# 是加载entry_pgdir的物理地址到cr3寄存器中。
	movl	$(RELOC(entry_pgdir)), %eax
	movl	%eax, %cr3
     
   # 开启分页  
	movl	%cr0, %eax
	orl	$(CR0_PE|CR0_PG|CR0_WP), %eax
	movl	%eax, %cr0

	# 注意，第一句mov $relocated, %eax 是将 relocated的链接地址加载到eax寄存器中，
	# 后一句 jmp *%eax 则是跳转到relocated的地址处执行。
	mov	$relocated, %eax 
	jmp	*%eax
relocated:

	# 清空栈指针寄存器 ebp
	movl	$0x0,%ebp			

	# 设置栈寄存器
	movl	$(bootstacktop),%esp

	# 转向C语言函数
	call	i386_init
```


初始化页目录和页表项代码如下，将 [0, 4MB) 和 [KERNBASE, KERNBASE+4MB)都映射到了物理地址 [0, 4MB)。页目录为 1024 个，我们只初始化了2个，且页目录项的值为页表数组的起始物理地址。页表初始化了 1024 个，每个指向大小为4KB的页，页表项的结构下一节会详细分析。开启分页后，CPU访问的地址会经由 虚拟地址 -> 线性地址 -> 物理地址 转换，这个转换由CPU内部的MMU部件来完成。MMU除了做地址转换之外，还提供内存保护机制。各种体系结构都有用户模和特权模式之分，操作系统可以在页表中设置每个内存页面的访问权限，有些页面不允许访问，有些页面只有在CPU处于特权模式时才允许访问，有些页面在两种模式下都可以访问。访问权限又分为可读、可写和可执行三种。当CPU要访问一个线性地址时，MMU会检查CPU当前处于用户模式还是特权模式，访问内存的目的是读数据、写数据还是取指令，如果和操作系统设定的页面权限相符，就允许访问，把它转换成物理地址，否则不允许访问，产生一个异常。

```
__attribute__((__aligned__(PGSIZE)))
pde_t entry_pgdir[NPDENTRIES] = {
	// 映射虚拟地址 [0, 4MB) 到物理地址 [0, 4MB)
	[0]
		= ((uintptr_t)entry_pgtable - KERNBASE) + PTE_P,
		
	// 映射虚拟地址 [KERNBASE, KERNBASE+4MB) 到物理地址 [0, 4MB)
   // PDXSHIFT是22，即取地址最高10位作为页目录的索引。
	[KERNBASE>>PDXSHIFT]
		= ((uintptr_t)entry_pgtable - KERNBASE) + PTE_P + PTE_W
};

// 第0项指向第0个物理页起始地址，第1项指向第1个物理页，按4KB对齐，以此类推。
__attribute__((__aligned__(PGSIZE)))
pte_t entry_pgtable[NPTENTRIES] = {
	0x000000 | PTE_P | PTE_W,
	0x001000 | PTE_P | PTE_W,
	0x002000 | PTE_P | PTE_W,
	......
	0x3ff000 | PTE_P | PTE_W,
}
```

而函数 `i386_init` 则是初始化了bss段内容为0(其中 edata 表示的是 bss 节在内存中开始的位置，而 end 则是表示内核可执行程序在内存中结束的位置)，调用调 cons_init 函数完成一系列的系统初始化，包括显存的初始化、键盘的初始化等。接着调用 cprintf 函数用 8 进制的形式打印一个 10 进制的数，但是此时 vprintfmt 函数中的关于打印 8 进制数的部分还没有实现，这是lab1的一个作业，所以这个时候会打印出如下的结果: `6828 decimal is XXX octal!`. `test_backtrace` 函数是通过堆栈来对函数调用进行回溯，后面再细说。最后程序无限循环的调用了 monitor 函数，用于提示用户输入命令与操作系统进行交互。

```
void
i386_init(void)
{
	extern char edata[], end[];

	// 初始化BSS段，保证静态和全局变量默认值为0
	memset(edata, 0, end - edata);

	// 初始化控制台，初始化之前不能调用cprintf
	cons_init();

	cprintf("6828 decimal is %o octal!\n", 6828);

	// 测试堆栈的函数
	test_backtrace(5);

	// monitor提示用户输入命令并与操作系统交互
	while (1)
		monitor(NULL);
}
```

# 7 显示输出

这里要完成 cprintf 函数的实现，注意可变参数的几个宏的实现，如 `va_start`，`va_end`。其中 va_list ap 其实是一个指针，va_start(ap, fmt)使ap指向fmt参数的下一个参数。然后我们就可以用 va_arg 宏依次读取之后的可变参数。在对参数指针进行了初始化后，程序接着调用了 vcprintf 函数，在得到 vcprintf 函数的返回值后，最后便使用 va_end 宏结束了对可变参数的获取，C标准要求在函数返回前调用va_end。

```
int
cprintf(const char *fmt, ...)
{
	va_list ap;
	int cnt;

	va_start(ap, fmt);
	cnt = vcprintf(fmt, ap);
	va_end(ap);

	return cnt;
}
```

cprintf 函数与指针 ap 的关系如下所示，在vcprintf中，调用了` vprintfmt((void*)putch, &cnt, fmt, ap);`，其中putch是输出函数，它调用了cputchar函数，最终cputchar调用了cga_putc函数来完成显示功能，在cga_putc函数中的crt_buf 是一个指向 16 位无符号整形数的静态指针，它实际上指向的是内存中物理地址为 0xb8000 的位置，在前面章节我们已经知道物理内存的 0xa0000 到 0xc0000 这 128KB 的空间是留给 VGA 显示缓存。在JOS中，显示屏规定为 25 行，每行可以输出 80 个字符，由于每个字符实际上占显存中的两个字节(字符ASCII码和字符属性)，于是物理内存中从 0xb8000 到 0xb8fa0 之间的内容都可以用字符的形式在屏幕上显示出来。

显示输出中参数的低 8 位是字符的 ASCII 码，而 8 到 15 位则是字符属性，字符属性高4位是背景色(IRGB)，低4位是前景色(IRGB)，其中RGB就是经典的红绿蓝三色，I表示字符是否高亮。当然cga_putc函数还考虑了显存溢出的问题，即在物理地址超过 0xb8fa0 的内存部分中存储字符数据，此时实际上显示屏就无法显示超出部分，此时显示屏会滚屏(将2~N+1行数据memmove拷贝到原来的 1~N 行)好让最新输出的字符能够显示出来。

```
      高地址->   +-----------------+
				|    可变参数n     |
				+-----------------+  
				|     .......     |
				+-----------------+ 
				|    可变参数2     |
				+-----------------+  
				|    可变参数1     |
				+-----------------+  <- ap
				|  格式参数fmt     |    
      低地址->   +-----------------+  
```

#8 函数调用堆栈
在JOS实验1中会有一个递归的调用，函数调用的回溯需要对调用栈有了解，先看一个例子：

```
// stack.c
int bar(int c, int d) {
	int e = c + d;
	return e;
}

int foo(int a, int b) {
	return bar(a, b);
}

int main() {
	foo(1, 2);
	return 0;
}
```
编译为汇编文件: `gcc -S -O0 -m32 -o stack.s stack.c`

```
// stack.s
bar:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$16, %esp
	movl	12(%ebp), %eax
	movl	8(%ebp), %edx
	addl	%edx, %eax
	movl	%eax, -4(%ebp)
	movl	-4(%ebp), %eax
	leave
	ret
foo:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$8, %esp
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	bar
	leave
	ret
main:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$8, %esp
	movl	$2, 4(%esp)
	movl	$1, (%esp)
	call	foo
	movl	$0, %eax
	leave
	ret
```
通过汇编文件 stack.s，我们可以看到函数调用时栈的变化。前面提到过，堆栈是由高地址向低地址扩展的，函数参数是从右往左压栈的。这里的call，leave和ret指令要说明下：

- call：将call的下一条指令压栈，然后修改eip寄存器的值并跳转到指定函数执行。
- leave：这个指令是函数开头的`pushl %ebp`和`movl %esp, %ebp`的逆操作，即将 ebp的值赋给 esp，这样esp指向的栈顶保存着上一个函数的 ebp 的值。然后执行 popl %ebp，将栈顶元素弹出到 ebp 寄存器，同时esp的值加4指向上一个函数的下一条指令地址。
- ret：弹出栈顶元素并将eip设置为该值，跳转到该地址执行。

而ret则是将栈顶。我们可以看到调用函数时堆栈如下：

```
+-----------------+  
|      b: 2       |
+-----------------+ 
|      a: 1       |
+-----------------+ 
|     ret(main)   |
+-----------------+   
|     ebp(main)   |
+-----------------+ <- ebp(foo)
|      d: 2       |
+-----------------+   
|      c: 1       |
+-----------------+   
|     ret(foo)    |
+-----------------+   
|     ebp(foo)    |
+-----------------+ <- ebp(bar)   
|      e: 3       |
+-----------------+   
```
由栈的分布可知，因为 esp 寄存器的值会随着pushl和popl操作而不断变化，为了追溯函数调用，需要用 ebp 寄存器来保存栈指针以串联各个函数之间关系。如在 bar 函数中可以通过ebp来找到自己的参数和局部变量，也可以找到 foo 函数中保存在栈上的值；而有了 foo 函数的ebp，foo函数则可以找到自己的参数和局部变量，也可以找到 main 保存在栈上的值。

在JOS中有个 test_backtrace()函数来跟踪函数调用过程，稍有不同的是用了递归(即同一个函数调用多次)，其实原理是一样的。

# 参考资料
- [https://pdos.csail.mit.edu/6.828/2017/labs/lab1/](https://pdos.csail.mit.edu/6.828/2017/labs/lab1/)
- 邵志远老师 《多核操作系统设计》讲义
- 《深入理解计算机系统》
- 宋劲松 《Linux一站式编程》
