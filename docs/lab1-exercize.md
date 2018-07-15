> JOS lab1 系统启动这块涉及到的理论知识较多，总结要很长时间，要全部弄明白也非一朝一夕的事情，这一篇来完成 lab1 中的练习题。
> 

# Exercize 1-4
熟悉 AT&T 汇编语言。使用 GDB 的 si 命令跟踪 ROM BIOS 的指令做了什么事情，大致理解原理即可。熟悉C语言，熟练使用GDB命令，如

```
(gdb) b *0x7c00   // 注意gdb的break参数是加载地址，也就是物理地址
Breakpoint 1 at 0x7c00
(gdb) c
Continuing.
[   0:7c00] => 0x7c00:	cli   

Breakpoint 1, 0x00007c00 in ?? ()
(gdb) info registers
eax            0xaa55	43605
ecx            0x0	0
edx            0x80	128
ebx            0x0	0
esp            0x6f20	0x6f20
ebp            0x0	0x0
esi            0x0	0
edi            0x0	0
eip            0x7c00	0x7c00
eflags         0x202	[ IF ]
cs             0x0	0
ss             0x0	0
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
(gdb) si
[   0:7c01] => 0x7c01:	cld    
0x00007c01 in ?? ()
(gdb) x /3i 0x7c01
=> 0x7c01:	cld    
   0x7c02:	xor    %ax,%ax
   0x7c04:	mov    %ax,%ds
```

几个问题的答案：

- 什么时候开始从 16 位模式转换到 32 位？

	开启保护模式后就从16位转换到了32位模式。代码如下：
	
	```
	  # Switch from real to protected mode, using a bootstrap GDT
	  # and segment translation that makes virtual addresses 
	  # identical to their physical addresses, so that the 
	  # effective memory map does not change during the switch.
	  lgdt    gdtdesc
	  movl    %cr0, %eax
	  orl     $CR0_PE_ON, %eax
	  movl    %eax, %cr0 
	```

- Boot Loader执行的最后一条指令是什么？

	Boot Loader的最后一条指令是跳转到 Kernel 入口的 call 指令。
	
	```
	  ((void (*)(void)) (ELFHDR->e_entry))();
	```
	从 `obj/boot/boot.asm`中可以看到对应的汇编语句是
	
	 ```
	 call   *0x10018
	 ```
	即跳转到 0x10018 内存地址所存储的值处运行，那么 0x10018 这个地址存储的内容是什么呢？可以看到正好是 0x10000c，即 Kernel的入口地址。
	
	```
	(gdb) x /1x 0x10018
	0x10018:	0x0010000c
	```
- Boot Loader 如何决定加载几个扇区到内存中的？
 	这是从 ELF 头知道的，由 e_phoff 知道第一个段的位置， 由 e_phnum 可以知道需要加载几个段。

# Exercize 5
修改 `boot/Makefrag` 中的链接地址 0x7C00 为一个错误地址 0x7C10，观察出错。之前在分析链接地址和加载地址区别时已经修改过，可以发现，在执行完 `ljmp $0x8, $0x7c42`这句指令后报错如下：

```
// 第一个终端
$ make qemu-nox-gdb
***
*** Now run 'make gdb'.
***
qemu-system-i386 -nographic -drive file=obj/kern/kernel.img,index=0,media=disk,format=raw -serial mon:stdio -gdb tcp::26000 -D qemu.log  -S
EAX=00000011 EBX=00000000 ECX=00000000 EDX=00000080
ESI=00000000 EDI=00000000 EBP=00000000 ESP=00006f20
EIP=00007c2d EFL=00000006 [-----P-] CPL=0 II=0 A20=1 SMM=0 HLT=0
ES =0000 00000000 0000ffff 00009300 DPL=0 DS16 [-WA]
CS =0000 00000000 0000ffff 00009b00 DPL=0 CS16 [-RA]
SS =0000 00000000 0000ffff 00009300 DPL=0 DS16 [-WA]
DS =0000 00000000 0000ffff 00009300 DPL=0 DS16 [-WA]
FS =0000 00000000 0000ffff 00009300 DPL=0 DS16 [-WA]
GS =0000 00000000 0000ffff 00009300 DPL=0 DS16 [-WA]
LDT=0000 00000000 0000ffff 00008200 DPL=0 LDT
TR =0000 00000000 0000ffff 00008b00 DPL=0 TSS32-busy
GDT=     0075403c 0000c0e0
IDT=     00000000 000003ff
CR0=00000011 CR2=00000000 CR3=00000000 CR4=00000000
DR0=00000000 DR1=00000000 DR2=00000000 DR3=00000000 
DR6=ffff0ff0 DR7=00000400
EFER=0000000000000000
Triple fault.  Halting for inspection via QEMU monitor.

# 第二个终端
$ make gdb
[f000:fff0]    0xffff0:	ljmp   $0xf000,$0xe05b
0x0000fff0 in ?? ()
+ symbol-file obj/kern/kernel
(gdb) b *0x7c2a
Breakpoint 1 at 0x7c2a
(gdb) c
Continuing.
[   0:7c2a] => 0x7c2a:	mov    %eax,%cr0

Breakpoint 1, 0x00007c2a in ?? ()
(gdb) si
[   0:7c2d] => 0x7c2d:	ljmp   $0x8,$0x7c42
0x00007c2d in ?? ()
(gdb) si
[   0:7c2d] => 0x7c2d:	ljmp   $0x8,$0x7c42
0x00007c2d in ?? ()
(gdb) 
```

# Exercize 6
从 BIOS 进入 Boot Loader的时候，因为还没有加载内核，0x100000 处内存还没有内容，所以 `x /8x 0x100000` 看到的都是0。而从 Boot Loader 进入 Kernel，此时kernel已经加载到内存中，因此有了对应的指令。可以简单验证：

```
(gdb) b *0x7c00
Breakpoint 1 at 0x7c00
(gdb) c
Continuing.
[   0:7c00] => 0x7c00:	cli    

Breakpoint 1, 0x00007c00 in ?? ()
(gdb) x /8wx 0x00100000
0x100000:	0x00000000	0x00000000	0x00000000	0x00000000
0x100010:	0x00000000	0x00000000	0x00000000	0x00000000
(gdb) b *0x10000c
Breakpoint 2 at 0x10000c
(gdb) c
Continuing.
The target architecture is assumed to be i386
=> 0x10000c:	movw   $0x1234,0x472

Breakpoint 2, 0x0010000c in ?? ()
(gdb) x /8wx 0x00100000
0x100000:	0x1badb002	0x00000000	0xe4524ffe	0x7205c766
0x100010:	0x34000004	0x0000b812	0x220f0011	0xc0200fd8
```

# Exercize 7
理解开启分页的效果，`mov %eax, %cr0` (链接地址0xf0100025，物理地址0x100025) 这条指令开启分页。开启分页前，高地址KERNBASE `0xf0000000`开始的内容映射还没有生效，内容为0，而开启了分页后，虚拟地址 [KERNBASE, KERNBASE+4M) 映射到了物理内存的 [0, 4M)，所以可以看到 0xf0100000 与 0x00100000 的内容是一样的。

```
(gdb) b *0x100025
Breakpoint 3 at 0x100025
(gdb) c
Continuing.
=> 0x100025:	mov    %eax,%cr0

Breakpoint 3, 0x00100025 in ?? ()
(gdb) x/8x 0x00100000
0x100000:	0x1badb002	0x00000000	0xe4524ffe	0x7205c766
0x100010:	0x34000004	0x0000b812	0x220f0011	0xc0200fd8
(gdb) x/8x 0xf0100000
0xf0100000 <_start+4026531828>:	0x00000000	0x00000000	0x00000000	0x00000000
0xf0100010 <entry+4>:	0x00000000	0x00000000	0x00000000	0x00000000
(gdb) si
=> 0x100028:	mov    $0xf010002f,%eax
0x00100028 in ?? ()
(gdb) x/8x 0x00100000
0x100000:	0x1badb002	0x00000000	0xe4524ffe	0x7205c766
0x100010:	0x34000004	0x0000b812	0x220f0011	0xc0200fd8
(gdb) x/8x 0xf0100000
0xf0100000 <_start+4026531828>:	0x1badb002	0x00000000	0xe4524ffe	0x7205c766
0xf0100010 <entry+4>:	0x34000004	0x0000b812	0x220f0011	0xc0200fd8

```
如果注释掉 `kernel/entry.S` 中的 `movl %eax, %cr0` 这条指令，因为高地址没有映射，执行完 ` jmp *%eax` 后跳转到 eax寄存器保存的值所在地址 0xf010002c 时会报如下错误：

```
qemu: fatal: Trying to execute code outside RAM or ROM at 0xf010002c
```

# Exercize 8
补全cprintf中的 %o 格式代码，仿照 %d 的实现如下：

```
--- a/lib/printfmt.c
+++ b/lib/printfmt.c
@@ -206,11 +206,9 @@ vprintfmt(void (*putch)(int, void*), void *putdat, const char *fmt, va_list ap)
                // (unsigned) octal
                case 'o':
                        // Replace this with your code.
-                       putch('X', putdat);
-                       putch('X', putdat);
-                       putch('X', putdat);
-                       break;
-
+                       num = getuint(&ap, lflag);
+                       base = 8;
+                       goto number;
                // pointer
                case 'p':
                        putch('0', putdat);
```
注意，如果用 %x 打印负数，因为%x是打印无符号数的十六进制，而-3的补码是0xfffffffd，所以，打印负数的十六进制会输出补码。 

```
int x = -1, y = -3, z = -4;
cprintf("x %d, y %x, z %d\n", x, y, z);

// 输出
x -1, y fffffffd, z -4
```

其他问题：

1. console.c 导出了 cputchar，getchar等函数。printf.c 的 vprintfmt 函数中使用了 putch函数作为参数，而putch函数调用了console.c中的cputchar。
2. console.c中的下面这段代码作用是实现屏幕滚动一行。

	```
	1      if (crt_pos >= CRT_SIZE) {
	2              int i;
	3              memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
	4              for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
	5                      crt_buf[i] = 0x0700 | ' ';
	6              crt_pos -= CRT_COLS;
	7      }
	```
3. fmt指向的是参数中的格式字符串，而ap指向fmt的后一个参数地址，详见理论篇分析。
4. 下面代码输出是 `He110 World`，因为 57616 转换为16进制是 0xe110，所以有He110，而0x00646c72对应的字符分别是0dlr，而因为x86采用的是小端模式，即低位数字存在低地址处，于是按照地址从低到高正好是 rld0，显示对应的是 World。
	
	```
	unsigned int i = 0x00646c72;
	cprintf("H%x Wo%s", 57616, &i);
	```
5. 如果fmt里面指定的格式化字符串数目大于实际参数数目，因为缺少参数，而由可变参数的方式知道会打印第一个参数之上的栈里面的4字节内容，在我的实验环境显示的是 `x=3 y=-267321364`。

6. 如果GCC参数入栈方式改为从左往右，则可能需要加一个表示参数个数的参数传到cprintf函数中以获取可变参数。


# Exercize 9
找到栈的初始化代码以及栈内存分配的位置，以及kernel是如何为栈保存空间的？以及保存的栈空间的结束位置在哪里？

在`kernel/entry.S`中分配了栈空间，栈大小是KSTKSIZE，即8*4KB = 32KB 大小。代码如下：

```
relocated:

	# Clear the frame pointer register (EBP)
	# so that once we get into debugging C code,
	# stack backtraces will be terminated properly.
	movl	$0x0,%ebp			# nuke frame pointer

	# Set the stack pointer
	movl	$(bootstacktop),%esp

......	
.data
###################################################################
# boot stack
###################################################################
	.p2align	PGSHIFT		# force page alignment
	.globl		bootstack
bootstack:
	.space		KSTKSIZE
	.globl		bootstacktop   
bootstacktop:

```
从 `obj/kernel/kernel.asm`中可以看到栈顶是 `0xf0110000`，栈是由高地址往地地址扩展的。

```
56         # Set the stack pointer
57         movl    $(bootstacktop),%esp
58 f0100034:       bc 00 00 11 f0          mov    $0xf0110000,%esp
```

# Exercize 10
熟悉x86里面的C语言函数调用规则，查看ebp，eip等寄存器的值。

```
[f000:fff0]    0xffff0:	ljmp   $0xf000,$0xe05b
0x0000fff0 in ?? ()
+ symbol-file obj/kern/kernel
(gdb) b i386_init
Breakpoint 1 at 0xf010009d: file kern/init.c, line 24.
(gdb) b test_backtrace
Breakpoint 2 at 0xf0100040: file kern/init.c, line 13.
(gdb) b mon_backtrace
Breakpoint 3 at 0xf01007ff: file kern/monitor.c, line 59.
(gdb) c
Continuing.
The target architecture is assumed to be i386
=> 0xf010009d <i386_init>:	push   %ebp

Breakpoint 1, i386_init () at kern/init.c:24
24	{
(gdb) si
=> 0xf010009e <i386_init+1>:	mov    %esp,%ebp
0xf010009e	24	{
(gdb) si
=> 0xf01000a0 <i386_init+3>:	sub    $0x28,%esp
0xf01000a0 in i386_init () at kern/init.c:24
24	{
(gdb) i r
eax            0xf010002f	-267386833
ecx            0x0	0
edx            0x9d	157
ebx            0x10094	65684
esp            0xf010fff8	0xf010fff8
ebp            0xf010fff8	0xf010fff8
esi            0x10094	65684
edi            0x0	0
eip            0xf01000a0	0xf01000a0 <i386_init+3>
eflags         0x86	[ PF SF ]
cs             0x8	8
ss             0x10	16
ds             0x10	16
es             0x10	16
fs             0x10	16
gs             0x10	16
(gdb) c
Continuing.
=> 0xf0100040 <test_backtrace>:	push   %ebp

Breakpoint 2, test_backtrace (x=5) at kern/init.c:13
13	{
(gdb) si
=> 0xf0100041 <test_backtrace+1>:	mov    %esp,%ebp
0xf0100041	13	{
(gdb) si
=> 0xf0100043 <test_backtrace+3>:	push   %ebx
0xf0100043	13	{
(gdb) i r
eax            0x0	0
ecx            0x3d4	980
edx            0x3d5	981
ebx            0x10094	65684
esp            0xf010ffc8	0xf010ffc8
ebp            0xf010ffc8	0xf010ffc8
esi            0x10094	65684
edi            0x0	0
eip            0xf0100043	0xf0100043 <test_backtrace+3>
eflags         0x86	[ PF SF ]
cs             0x8	8
ss             0x10	16
ds             0x10	16
es             0x10	16
fs             0x10	16
gs             0x10	16
(gdb) delete 2
(gdb) c
Continuing.
=> 0xf01007ff <mon_backtrace>:	push   %ebp

Breakpoint 3, mon_backtrace (argc=0, argv=0x0, tf=0x0) at kern/monitor.c:59
59	{
(gdb) si
=> 0xf0100800 <mon_backtrace+1>:	mov    %esp,%ebp
0xf0100800	59	{
(gdb) si
=> 0xf0100802 <mon_backtrace+3>:	push   %edi
0xf0100802	59	{
(gdb) i r
eax            0x0	0
ecx            0x3d4	980
edx            0x3d5	981
ebx            0x0	0
esp            0xf010ff08	0xf010ff08
ebp            0xf010ff08	0xf010ff08
esi            0x10094	65684
edi            0x0	0
eip            0xf0100802	0xf0100802 <mon_backtrace+3>
eflags         0x46	[ PF ZF ]
cs             0x8	8
ss             0x10	16
ds             0x10	16
es             0x10	16
fs             0x10	16
gs             0x10	16
```

# Exercize 11
完成 mon_backtrace 函数。主要是清楚堆栈存储数据的方式，寄存器ebp保存的是调用该函数的函数的ebp的地址，我们取出寄存器ebp中保存的值，可以得到调用该函数的函数的ebp值在栈中的地址，然后可以根据地址取到调用该函数的函数的ebp的值，如此可以得到所有调用的函数链的ebp值和参数，eip等。从之前的分析可以知道，ebp寄存器初始值是 0，当 ebp 为0时，我们停止循环。函数实现代码如下：

```
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	int i;
	uint32_t eip;
	uint32_t* ebp = (uint32_t *)read_ebp();

	while (ebp) {
		eip = *(ebp + 1);
		cprintf("ebp %x eip %x args", ebp, eip);
		uint32_t *args = ebp + 2;
		for (i = 0; i < 5; i++) {
			uint32_t argi = args[i];
			cprintf(" %08x ", argi);
		}
		cprintf("\n");
		ebp = (uint32_t *) *ebp;
	}
	return 0;
}
```

按照实验要求，每一个函数输出 5 个参数，从结果可以看到共输出了 8 个函数的信息，包括 test_backtrace 的 6 次调用， 以及 mon_backtrace 与 i386_init 函数，可以看到输出结果与Exercize 10的一致。

```
...
entering test_backtrace 5
entering test_backtrace 4
entering test_backtrace 3
entering test_backtrace 2
entering test_backtrace 1
entering test_backtrace 0
ebp f010ff08 eip f0100087 args 00000000  00000000  00000000  00000000  f01009a3  // mon_backtrace
ebp f010ff28 eip f0100069 args 00000000  00000001  f010ff68  00000000  f01009a3  // test_backtrace(5)
ebp f010ff48 eip f0100069 args 00000001  00000002  f010ff88  00000000  f01009a3 
ebp f010ff68 eip f0100069 args 00000002  00000003  f010ffa8  00000000  f01009a3 
ebp f010ff88 eip f0100069 args 00000003  00000004  00000000  00000000  00000000 
ebp f010ffa8 eip f0100069 args 00000004  00000005  00000000  00010094  00010094 
ebp f010ffc8 eip f0100144 args 00000005  00000003  f010ffec  fffffffc  00000000 
ebp f010fff8 eip f010003e args 00111021  00000000  00000000  00000000  00000000  // i386_init
leaving test_backtrace 0
leaving test_backtrace 1
leaving test_backtrace 2
leaving test_backtrace 3
leaving test_backtrace 4
leaving test_backtrace 5
Welcome to the JOS kernel monitor!
```

# Exercize 12
打印 `mon_backtrace()` 中对应每个 eip 的函数名、文件名和行号，在`kern/kdebug.c`中的函数 `debuginfo_eip()`添加查询行号的代码，然后完善 `mon_backtrace` 函数打印文件名、函数名及行号信息。

在编译内核的时候，我们可以看到加了 `-Wall -Wno-format -Wno-unused -Werror -gstabs -m32`，通过-gstabs参数在可执行文件中加了调试信息。

常见的stabs和stabn的定义如下：

```
.stabs "string",type,other,desc,value
.stabn type,other,desc,value
```

其中string的格式为`"name:symbol-descriptor type-information"
`.

参见 `inc/stab.h` 可以看到stabs结构的定义和常见的stabs类型：

```
struct Stab {
	uint32_t n_strx;	// index into string table of name
	uint8_t n_type;         // type of symbol
	uint8_t n_other;        // misc info (usually empty)
	uint16_t n_desc;        // description field
	uintptr_t n_value;	// value of symbol
};

#define	N_FUN		0x24	// procedure name
#define	N_SLINE		0x44	// text segment line number
#define	N_SO		0x64	// main source file name
#define	N_SOL		0x84	// included source file name
```

看一个简单的例子：

```
#include<stdio.h>
int main()
{
	printf("hello world\n");
	return 0;
}

int foo(int a) {
	printf("function foo\n");
	return 0;
}
```
运行命令：
```
gcc -Wno-format -Wno-unused -Werror -gstabs -m32 -S -o hello.s hello.c 
```
可以看到 hello.s 中的一些stabs：

```
	.stabs	"hello.c",100,0,2,.Ltext0
	.text
.Ltext0:
...
	.stabs	"main:F(0,1)",36,0,0,main
	
main:
	.stabn	68,0,3,.LM0-.LFBB1
	.stabs	"foo:F(0,1)",36,0,0,foo
	.stabs	"a:p(0,1)",160,0,0,8
foo:
	.stabn	68,0,8,.LM4-.LFBB2

```
其中第1行是描述源文件信息的，文件名是 hello.c，类型是N_SO（100），后面的desc=2表示C语言文件，.Ltext0为文件对应代码区的开始地址。

第2行stabs是描述main函数的，内容分别是函数名，函数类型F(全局），以及返回值为int。类型为 N_FUNC (36)，后面的main是函数起始地址。第4行stabs描述foo函数，同理。

第3行的stabn描述的是行号信息，其中 68 是类型 N_SLINE，后面的0是other值，不用管。而desc为3是main函数在源文件中的行号，value是源代码行的起始地址。第5行的stabn同理。关于stabs的详细信息请参考 `http://sourceware.org/gdb/onlinedocs/stabs.html`.

最终debuginfo_eip函数添加代码如下

```
stab_binsearch(stabs, &lline, &rline, N_SLINE, addr);
if (lline <= rline) {
    info->eip_line = stabs[rline].n_desc;
} else {
    return -1;
}
```

mon_backtrace添加代码如下：

```
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
   ...
	while (ebp) {
		...
		struct Eipdebuginfo debug_info;
		debuginfo_eip(eip, &debug_info);
		cprintf("\t%s:%d: %.*s+%d\n",
			debug_info.eip_file, debug_info.eip_line, debug_info.eip_fn_namelen,
			debug_info.eip_fn_name, eip - debug_info.eip_fn_addr);
		...
	}
	return 0;
}
```

参考资料：

- [https://github.com/Clann24/jos/tree/master/lab1](https://github.com/Clann24/jos/tree/master/lab1)
- [http://sourceware.org/gdb/onlinedocs/stabs.html](http://sourceware.org/gdb/onlinedocs/stabs.html`)
