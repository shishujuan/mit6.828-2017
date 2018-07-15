# 1 QEMU 虚拟网络
实验中将使用到QEMU的用户模式网络栈，因为它不需要管理员权限。JOS中通过更新makefile来启用QEMU的用户模式的网络栈以及虚拟的E1000网卡。

QEMU默认提供了一个在IP地址10.0.2.2上运行的虚拟路由器，它会为JOS分配一个IP地址10.0.2.15。为简单起见，我们将这些默认值硬编码到了 `net/ns.h`。

```
// net/ns.h
#define IP "10.0.2.15"
#define MASK "255.255.255.0"
#define DEFAULT "10.0.2.2"
```

虽然QEMU的虚拟网络允许JOS与互联网建立任意连接，但是JOS的IP地址10.0.2.15对于外部网络来说并无意义（这是一个内网地址，而QEMU就充当了NAT的角色）。因此，我们无法直接连接到运行在JOS内部的网络服务器，即便是从运行QEMU的宿主机连接。为了解决该问题，我们将QEMU配置为在主机上的某个端口上运行服务器，该端口只需连接到JOS中的某个端口，并在真实主机和虚拟网络之间传送数据。你将在端口7（echo）和80（http）上运行JOS服务器。要查找QEMU在开发主机上转发的端口，请运行make which-ports。

```
# make which-ports
Local port 26001 forwards to JOS port 7 (echo server)
Local port 26002 forwards to JOS port 80 (web server)
```

### 抓包
QEMU的虚拟网络栈会将进出的数据包记录到 qemu.pcap 文件中，可以通过tcpdump来查看。

```
tcpdump -XXnr qemu.pcap
```

# 2 网络服务器
从头开始编写网络堆栈很难。为此，我们将使用lwIP，一种开源轻量级包含了网络栈的 TCP / IP协议套件。在这个实验中，lwIP是一个黑盒子，它实现了一个BSD套接字接口，并有一个数据包输入和输出端口。

该网络服务器实际上是下面四个进程组合，下图展示了它们之间的关系。在本实验中要完成绿色标记的四个部分。

- core network server environment(包括socket 调用分发和lwIP)
- input environment
- output environment
- timer environment

![](https://pdos.csail.mit.edu/6.828/2017/labs/lab6/ns.png)

## 2.1 Core Network Server Environment
core network server 进程由socket调用和分发以及lwIP本身组成。其中调用和分发工作原理类似文件服务器。用户进程使用stubs(lib/nsipc.c)发送IPC消息给core network server进程，对于每个用户进程IPC，网络服务器中的调度程序都会调用lwIP中提供的响应的BSD套接字接口函数。

常规用户进程并不直接使用nsipc_* 这样调用，它们使用 `lib/sockets.c` 中的函数。sockets.c中提供了基于文件描述符的套接字API，用户环境通过文件描述符引用套接字，就像它们引用磁盘文件一样。有许多操作(connect， accept)对于socket的文件描述符是特有的，不过像read，write，close则是跟文件服务器一样。

尽管看起来文件服务器和网络服务器的IPC调度很相似，但存在一个关键的区别：**accept和recv这样的BSD套接字调用可以无限阻塞。**如果调度器执行一个阻塞式的调用，则调度器也会阻塞，并且整个系统一次只能有一个未完成的网络调用，这是不可接受的，因此网络服务器使用用户级线程来避免阻塞整个服务器。对于每个传入的IPC消息，调度器都会创建一个线程并在新创建的线程中处理该请求。如果线程阻塞，那么只有那个线程进入休眠状态，而其他线程继续运行。此外，还有三个辅助进程，下面一一介绍。

## 2.2 Output Environment
当lwIP接收用户进程的socket调用时，它会生成用于网卡传输的数据包(如TCP/ARP包等)。lwIP使用NSREQ_OUTPUT IPC消息发送数据包到output进程(数据包通过IPC的页共享）。output进程接收IPC消息，通过我们要实现的系统调用 `sys_pkt_send` 将数据包发送至网卡驱动中。

## 2.3 Input Environment
网卡接收的数据包需要导入到lwIP中。对网卡接收到的每个数据包，input进程将从内核空间拉取数据包(通过我们实现的读取数据包的系统调用 sys_pkt_receive)，然后通过NSREQ_INPUT IPC消息将数据包发送到core network server进程中。

input进程的功能从core network server进程中分离出来是因为同时接收IPC以及接收或等待来自设备驱动的数据包对于JOS是非常困难的，因为JOS中没有select这样能够允许进程监听多个输入源并判断输入源是否已经准备就绪。

## 2.4 Timer Environment
timer进程会定期向 core network server 进程发送 NSREQ_TIMER 的消息通知它某个计时器已经过时，它用于实现各种网络超时。

# 3 PCI接口、MMIO、DMA
以太网卡中数据链路层的芯片一般简称为MAC控制器，物理层的芯片简称为PHY。此外还有DMA，DMA会用到FIFO buffer，DMA用于提高传输效率，不用CPU控制，直接在网卡和主存之间传输数据。

EEPROM 用于存储产品配置信息。分为几个区域:

- 硬件访问区域 - 加电后被网卡控制器加载，D3->D0传输。
- ASF访问区域 - ASF模式启动后加载。
- 软件访问区域。

### PCI接口
pci_init时扫描总线读取外设信息，通过VENDER_ID和DEVICE_ID在pci_attach()查找设备，如果找到了设备，则会调用对应设备的attach函数初始化对应设备，然后在 struct pci_func中填充读取到的配置信息。其中82450EM的 VENDER_ID 为 0x8086，DEVICE ID为0x100e，在5.2中可以找到。reg_base和reg_size数组存储Base Address Register（BAR）的信息，BAR的作用就是用于说明该设备想在主存中映射多少内存空间和起始位置，一个网卡通常有6个32位的BAR或者3个64位的BAR。reg_base记录了memory-mapped IO region的基内存地址或者基IO端口，reg_size则记录了reg_base对应的内存区域的大小或者IO端口的数目，irq_line是分配给设备中断用的IRQ线。 

在pci_scan_bus中会设置好pic_func的dev_id，dev_class，dev，bus等值，而reg_base，reg_size，irq_line则是需要通过设备的attach函数调用pci_func_enable()中来初始化。如实验中的网卡的函数我们定义在 kern/e1000.c 中，名为 `e1000_attach()`。

### MMIO
其中初始化了设备外，还要设置好MMIO映射，这里映射的物理地址是 reg_base[0](测试网卡的物理地址为 0xfebc0000)，大小为 reg_size[0](大小为0x20000=128K)，即我们映射了 BAR[0]，第0个基地址寄存器，然后将MMIO映射的虚拟地址保存到一个全局变量中（映射虚拟地址是 0xef804000）。


```
struct pci_func {
    struct pci_bus *bus;	// Primary bus for bridges

    uint32_t dev;
    uint32_t func;

    uint32_t dev_id;
    uint32_t dev_class;

    uint32_t reg_base[6];
    uint32_t reg_size[6];
    uint8_t irq_line;
};
```

pci读取总线获取PCI设备配置的操作通过两个IO端口实现，一个是地址端口0xcf8，一个是数据端口0xcfc。具体通过 pci_conf_read 和 pci_conf_write 两个函数实现，没有探究细节了，大致原理就是在对应IO端口读取写入配置。

```
 static uint32_t pci_conf1_addr_ioport = 0x0cf8;
 static uint32_t pci_conf1_data_ioport = 0x0cfc;   
```

### DMA
可以想象的是，从E1000的寄存器来接收和传输数据，效率会很低，而且要求E1000内部来缓存数据包。为此，E1000采用了DMA来直接在网卡和主存之间传输数据，而不用CPU的参与。驱动程序负责为发送队列和接收队列分配内存，设置DMA描述符，并为E1000配置这些队列的位置，之后的流程都是异步的。传输数据包时，驱动程序将数据包复制到传输队列中的下一个DMA描述符中，并通知E1000另一个数据包可用，等到发送数据包的时候，E1000从DMA描述符复制出数据包。同样，当E1000接收到一个数据包时，它将它复制到接收队列中的下一个DMA描述符中，驱动程序可以在下一次读取它。

接收和发送队列从顶层看来非常相似，两者都由一系列描述符组成。尽管这些描述符的确切结构各不相同，但每个描述符都包含一些标志和包含分组数据的缓冲区的物理地址（要么是网卡待发送的分组数据，要么由操作系统分配的缓冲区以便网卡存入接收到的数据包）。

队列实现为循环数组，这意味着当网卡或驱动程序到达数组的末尾时，它会转回到头部。两者都有一个头指针header和一个尾指针tail，数组项是DMA描述符。网卡总是消耗来自头部的描述符并移动头指针，而驱动程序总是将DMA描述符添加到尾部并移动尾指针。传输队列中的描述符表示等待发送的数据包（因此，在稳定状态下，传输队列为空）。接收队列中的描述符是网卡可以接收数据包的空闲描述符（因此，在稳定状态下，接收队列由所有可用的接收描述符组成）。

这些数组指针以及描述符中数据包缓冲区的地址都必须是物理地址，因为硬件直接在物理内存上执行DMA，而不通过MMU，不经过分页转换。

# 4 传输数据包
## 4.1 传输描述符格式和初始化
E1000的发送和接收数据包的功能基本是独立的，因此我们可以分开来实现。我们首先实现传输数据包功能，因为如果不先实现传输功能我们无法测试接收数据包功能。

首先，我们要按照文档14.5节中描述的步骤初始化要发送的网卡（不用过多关注细节）。传输初始化的第一步是设置传输队列。队列的结构在3.4节中描述，描述符的结构在3.3.3节中描述。我们不会使用E1000的`TCP offload`功能，因此关注`legacy transform descriptor format`即可。

为描述E1000的结构，使用C语言中的结构体十分方便。比如对于文档3.3.3节表3-8中描述的`legacy transform descriptor format`：

```
  63            48 47   40 39   32 31   24 23   16 15             0
  +---------------------------------------------------------------+
  |                         Buffer address                        |
  +---------------+-------+-------+-------+-------+---------------+
  |    Special    |  CSS  | Status|  Cmd  |  CSO  |    Length     |
  +---------------+-------+-------+-------+-------+---------------+
```

发送描述符可以用下面的结构体来描述：

```
struct tx_desc
{
	uint64_t addr;
	uint16_t length;
	uint8_t cso;
	uint8_t cmd;
	uint8_t status;
	uint8_t css;
	uint16_t special;
};
```

你的驱动程序必须为发送描述符数组和发送描述符指向的数据包缓冲区保留内存。有几种方法可以做到这一点，如动态分配页面或者简单地在全局变量中声明。无论哪种方式，请记住E1000直接访问物理内存，这意味着它访问的任何缓冲区必须在物理内存中连续。

还有多种方法来处理数据包缓冲区。比较简单的方式是在驱动程序初始化期间为每个描述符保留数据包缓冲区的空间，并简单地将数据包数据复制到这些预分配的缓冲区中。以太网数据包的最大为1518字节，可以根据这个设置缓冲区的大小。更复杂的驱动程序可以动态地分配数据包缓冲区或者传递由用户空间直接提供的缓冲区（称为“零拷贝”的技术）。

根据文档14.5中描述完成网卡初始化。寄存器初始化参照文档13章，传输描述符及其数组参照3.3.3和3.4节。注意传输描述符数组的对齐要求和数组长度限制。TDLEN必须是128字节对齐，每个传输描述符长度为16字节，传输描述符数组的描述符数目必须是8的整数倍，不过不要超过64个，否则会影响ring overflow测试。对于TCTL.COLD，您可以认为是全双工操作。

查看文档14.5节，可以看到网卡初始化步骤如下：

- 为发送描述符队列分配一块内存，并设置传输描述符基地址寄存器(Transmit Descriptor Base Address，TDBAL/TDBAH) 为分配内存的地址。
- 设置传输描述符长度寄存器(Transmit Descriptor Length，TDLEN)寄存器的值为描述符队列的大小，必须128字节对齐。
- 设置发送描述符的header和tail指针为0.
- 根据需要初始化传输控制寄存器( Transmit Control Register， TCTL）：
	- 设置TCTL.EN位为1以支持常规操作。
	- 设置 Pad Short Packets(TCTL.PSP) 为1.
	- 设置 Collision Threshold(TCTL.CT)位为需要的值。以太网标准是设置为0x10，这个设置在半双工模式中有用。
	- 设置 Collision Distance (TCTL.COLD)为期望的值。在全双工模式设置为0x40，在1000M半双工网络这个值设置为0x200，在10/100M半双工设置为0x40，我们这里设置为0x40。
- 设置 Transmit IPG(TIPG)寄存器的IPGT,IPGR1和IPGR2的值。TIPG用于设置`legal Inter Packet Gap`。TIPG设置参考13.4.34中的表13-77，分别将ipgt设置为10，ipgr1设为4(ipgr2的2/3)，ipgr2设置为6。

根据要求来设置传输描述符和描述符数组，采用简单点的方式，描述符数组和packet buffer全部采用数组方式。当我们传输数据包时，如果设置了描述符的cmd参数为RS，则当网卡发送完数据包时，会设置DD位，即设置描述符中的status对应位，我们可以根据DD位来判断当前描述符是否可以重用，如果DD置位了，则表示可以回收并重新使用了。

传输数据包函数如果正确的话，`make E1000_DEBUG=TXERR,TX run-net_testoutput`会输出如下，其中index是描述符数组索引，后面的0x302040是packet buffer地址，而9000009是cmd/CSO/length值(因为我们设置了RS和EOP位，所以cmd为8位0x09，CSO为8位0x00，length为16为0x0009，表示长度为9)，0是special/CSS/status值。

```
Transmitting packet 1
e1000: index 0: 0x302040 : 9000009 0
Transmitting packet 2
e1000: index 1: 0x30262e : 9000009 0
Transmitting packet 3
e1000: index 2: 0x302c1c : 9000009 0
```
如果遇到很多`"e1000: tx disabled"`提示信息，则说明你的TCTL寄存器没有设置正确。

## 4.2 output helper进程
现在在网卡驱动传输端有了一个系统调用，输出进程的目标就是循环执行下面操作：

- 从网络服务器进程接收NSREQ_OUTPUT IPC消息
- 使用新添加的系统调用(sys_pkg_send)将IPC消息中附带的数据包发送给网卡。

NSREQ_OUTPUT IPC消息是lwip的`net/lwip/jos/jif/jif.c`中的low_level_output发送的，IPC消息中会包含一个共享页，这个页内容是一个union Nsipc，其中有一个`struct jif_pkt pkt`，而 jif_pkt结构体定义如下，其中jp_len是数据包长度，而jp_data则是数据内容。这里用到长度为0的数组的技巧。

```
struct jif_pkt {
    int jp_len;
    char jp_data[0];
};
```

注意网卡驱动，输出进程以及网络服务器进程之间的交互。当网络服务器进程通过IPC发送数据包给输出进程时，如果此时因为网卡驱动没有更多buffer导致输出进程挂起，则网络服务器进程必须阻塞等待。这里的流程是：

```
core network env -> output helper env -> e1000 driver
```

# 4 接收数据包及input helper进程

类似传输数据包，接下来完成接收数据包流程。这里要设置接收描述符和接收描述符队列，接收描述符和队列结构在文档3.2节描述，而初始化细节在 14.4节。

接收的描述符的队列大小这里设置的是128个，另外，而E1000_RA 这个设置MAC地址时要注意，比如我们测试的MAC地址是 `52:54:00:12:34:56`，则ral处要设置为 0x12005452，而rah则要设置为 0x5634| E1000_RAH_AV，E1000_RAH_AV标识地址有效。

RDH寄存器指向网卡可存放数据包的第一个描述符，当网卡接收到数据包时，会将数据包存入接收队列，并将RDH寄存器的值加1，这个更新寄存器的值的操作是网卡硬件执行的。

RDT寄存器则是存放的是网卡可用用来存放数据包的最后一个描述符的下一个描述符，这里我们设置为127，即浪费一个描述符作为标识，我们的队列最多可以存放127个数据包。

而测试程序`net/testinput.c`主要是做了下面几个事情：

- 创建一个子进程运行 output()，一个子进程运行input()，然后通过lwip构建一个ARP报文并发送给output environment。ARP报文通过 ipc_send()发送NSREQ_OUTPUT类型的IPC消息给output 进程。
- output 进程接收到IPC消息后，会读取IPC映射页中数据包内容，调用系统调用 sys_pkt_send() 将数据包发送到网卡的发送描述符队列中，发送程序就是我们实现的 e1000_transmit()函数。
- 而当网卡接收到ARP请求后，会响应请求并输出响应到我们设置的接收描述符队列中。
- 网卡输出完毕后，会设置接收描述符的DD标记，此时input进程从接收描述符接收到网卡的数据包，并将其发送给core network server 进程。注意这里，每次接收后发送要间隔一段时间，因为网络服务器进程读取数据需要一定时间。

# 5 WEB服务器
最后是实现web服务器，类似httpd，主要完成send_file和send_data函数。实现就是根据请求解析出文件名，然后调用 fstat 获取文件大小类型等元数据，并调用readn读取文件以及使用writen写入文件数据到socket中。

注意这里的accept，bind等函数都是 `lib/sockets.c`中定义的，最终都是通过IPC功能将请求发送至 core network server进程(ns/serv.c)，然后 core network server进程再调用的lwip来实现相关功能。这里用到了线程，线程实现在 `net/lwip/jos/arch/thread.c`中。


