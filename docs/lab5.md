# 1 文件系统初步
JOS文件系统设计相比Linux等系统的文件系统如ext2，ext3等，要简化不少。它不支持用户和权限特性，也不支持硬链接，符号链接，时间戳以及特殊设备文件等。

## 1.1 磁盘文件系统结构
大部分Unix文件系统会将磁盘空间分为inode和data两个部分，如linux就是这样的，其中inode用于存储文件的元数据，比如文件类型(常规、目录、符号链接等），权限，文件大小，创建/修改/访问时间，文件数据块信息等，我们运行的`ls -l`看到的内容，都是存储在inode而不是数据块中的。数据部分通常分为很多数据块，数据块用于存储文件的数据信息以及目录的元数据(目录元数据包括目录下文件的inode，文件名，文件类型等)。

文件和目录逻辑上都是由一系列数据块构成，可以像进程那样将虚拟地址空间映射到物理内存，文件系统需要隐藏数据块分布细节，对外只需要提供文件操作方法即可，如open，read，write，close等。JOS文件系统的实现跟Linux的不同，它没有使用系统调用实现，而是通过我们之前完成的IPC功能来实现文件操作的。系统会在启动时运行一个文件系统进程，该进程接收用户进程的IPC请求并完成文件的各种操作。

## 1.2 磁盘扇区、数据块、超级块
扇区是磁盘的物理属性，通常一个扇区大小为512字节，而数据块则是操作系统使用磁盘的一个逻辑属性，一个块大小通常是扇区的整数倍，在JOS中一个块大小为4KB，跟我们物理内存的页大小一致。

文件系统通常会保留一些磁盘上很容易找到的数据块用于存储磁盘的元数据，这些特殊的块叫超级块(superblock)。JOS中有一个超级块，用的块1用作超级块。块0通常保留给启动块和分区，所以文件系统没有使用块0做超级块。

![块分布](https://pdos.csail.mit.edu/6.828/2017/labs/lab5/disk.png)

## 1.3 文件元数据
JOS的文件元数据存储在 `inc/fs.h` 的 `struct File`中。元数据包括文件名，文件大小，文件类型以及指向的数据块。因为JOS没有使用inode，元数据信息就存储在磁盘的目录项中，不像Linux那样，JOS使用同一个 File 结构存储了磁盘和内存中的文件元数据。

```
struct File {
	char f_name[MAXNAMELEN];	// filename
	off_t f_size;			// file size in bytes
	uint32_t f_type;		// file type

	// Block pointers.
	// A block is allocated iff its value is != 0.
	uint32_t f_direct[NDIRECT];	// direct blocks
	uint32_t f_indirect;		// indirect block

	// Pad out to 256 bytes; must do arithmetic in case we're compiling
	// fsformat on a 64-bit machine.
	uint8_t f_pad[256 - MAXNAMELEN - 8 - 4*NDIRECT - 4];
} __attribute__((packed));	// required only on some 64-bit machines
```

struct File中的f_direct数组存储了前10个数据块的块号，这10个数据块是直接块。每个块为4KB，所以直接块可以存储40KB内的小文件。而对于大文件，File中还支持一个间接块，间接块可以存储 4096/4 = 1024 个块号，即JOS中最大可以存储1034个块大小的文件，即最大支持4MB左右的文件。在Linux中，还有二级间接块以及三级间接块等，用于存储更大的文件。

![文件元数据](https://pdos.csail.mit.edu/6.828/2017/labs/lab5/file.png)

## 1.4 文件和目录
JOS文件系统中的struct File 可以代表一个常规文件或者目录，通过 f_type 来区分。文件系统管理常规文件和目录文件采用的是一样的方式，唯一区别是对常规文件，文件系统并不解析数据块内容，而对于目录，则会将数据内容解析为 struct File 的格式。

JOS文件系统中的超级块包含了一个 struct File结构的字段root，用于存储文件系统的根目录元数据。根目录文件的数据块存储的则是该目录下的文件的元数据，如果根目录下有子目录，则这里会存储子目录的元数据。

# 2 文件系统实现
本实验我们要完成的功能包括：

- 读取磁盘中的数据块到块缓存以及将块缓存中的数据刷回磁盘。
- 分配数据块。
- 映射文件偏移到磁盘数据块。
- 在IPC接口实现文件的open，read，write，close。

文件系统镜像是在 `fs/fsformat.c` 中创建的，最终在QEMU中加载的文件系统镜像文件为 `obj/fs/fs.img`，其中内核镜像在磁盘0，文件系统镜像在磁盘1。文件系统的第0，1，2数据块分别用于启动块，超级块，以及块位图。而因为在文件系统中初始加入了 user 目录和fs 目录的一些文件，一共用掉了0-110块，所以空闲块从111开始。

```
qemu-system-i386 -drive file=obj/kern/kernel.img,index=0,media=disk,format=raw -serial 
mon:stdio -gdb tcp::26000 -D qemu.log -smp 1 -drive 
file=obj/fs/fs.img,index=1,media=disk,format=raw 

```

## 2.1 磁盘访问
不同于Linux等系统那样增加一个磁盘驱动并添加相关系统调用实现磁盘访问，JOS的磁盘驱动是用用户级程序实现的，当然还是要对内核做一点修改，以支持文件系统进程(用户级进程)有权限访问磁盘。

在用户空间访问磁盘可以通过轮询的方式实现，而不是使用磁盘中断的方式，因为使用中断的方式会复杂不少。x86处理器使用 EFLAGS 寄存器的 IOPL 位来控制磁盘访问权限(即IN和OUT指令)，用户代码能否访问IO空间就通过该标志来设置。JOS在i386_init()中运行了一个用户级的文件系统进程，该进程需要有磁盘访问权限。因此作业1就是在 env_create 中对 文件系统进程 这个特殊的运行在用户级的进程设置 IOPL 权限，而其他的用户进程不能设置该权限，根据进程类型设置权限即可。

```
ENV_CREATE(fs_fs, ENV_TYPE_FS);
```

特殊的文件系统进程代码在 `fs/fs.c`，它提供了`file_open，file_read，file_write，file_flush`文件操作函数以及`file_get_block, file_block_walk`数据块操作函数等。

## 2.2 块缓存

JOS文件系统将 0x10000000(DISKMAP) 到 0xD0000000(DISKMAP+DISKMAX）这个区间的地址空间映射到磁盘，即JOS可以处理3GB的磁盘文件。如0x1000000 映射到数据块0，0x10001000 映射到数据库1。块缓存代码在 `fs/bc.c` 中，其中 diskaddr 函数可以完成数据块号到虚拟地址的转换。

因为文件系统进程自己有地理的虚拟地址空间，所以让它保留3GB虚拟空间地址用于映射文件是没问题的。当然我们不会一次将文件全部读到内存中，JOS采用的是`demand paging`，即访问对应的磁盘块发生了页错误时才分配物理页。具体实现在 bc_pgfault 函数中，有点类似COW fork()的实现，ide_read() 的单位是扇区，不是磁盘块，通过 outb 指令设置读取的扇区数，通过insl指令读取磁盘数据到对应的虚拟地址addr处。bc_pgfault 中分配了一页物理页，然后从磁盘中读取出错的addr那一块数据(8个扇区）到分配的物理页中，然后清除分配页的dirty标记，最后调用 block_is_free 检查对应磁盘块确保磁盘块已经分配。注意这里检查磁盘块是否已经分配要在最后检查，是因为bitmap的值是在fs_init时指定的为diskaddr(2)，即0x10002000，在准备读取第二个磁盘块发生页错误进入bgfault时，此时bitmap对应块还没有从磁盘读取并映射好，所以要在最后检查。

flush_block()函数用于在写入磁盘数据到块缓存后，调用 ide_write() 写入块缓存数据到磁盘中。写入完成后，也要通过 sys_page_map() 清除块缓存的 dirty 标记(每次写入物理页的时候，处理器会自动标记该页为 dirty，即设置PTE_D标记)。注意，在flush_block()中，如果该地址并没有映射或者并没有dirty，则不需要做任何事情。

bc.c中的bc_init用于完成块缓存初始化，它完成下面几件事：

- 1）设置页错误处理函数为 bc_pgfault。
- 2）调用 check_bc() 检查块缓存设置是否正确。
- 3）读取磁盘块1的数据到函数局部变量super对应的地址中。(这一步没有什么作用，super变量也没有用到过，应该是老代码遗留问题)

## 2.3 块位图
在fs_init设置bitmap指针后，可以认为bitmap就是一个位数组，每个块占据一位。可以通过 block_is_free 检查块位图中的对应块是否空闲，如果为1表示空闲，为0已经使用。JOS中第0，1，2块分别给bootloader，superblock以及bitmap使用了。此外，因为在文件系统中加入了user目录和fs目录的文件，导致JOS文件系统一共用掉了0-110这111个文件块，下一个空闲文件块从111开始。

## 2.4 文件操作
在 fs/fs.c 中有很多文件操作相关的函数，这里的主要几个结构体要说明下：

- struct File 用于存储文件元数据，前面提到过。
- struct Fd 用于文件模拟层，类似文件描述符，如文件ID，文件打开模式，文件偏移都存储在Fd中。一个进程同时最多打开 MAXFD(32) 个文件。
- 文件系统进程还维护了一个打开文件的描述符表，即opentab数组，数组元素为 struct OpenFile。OpenFile结构体用于存储打开文件信息，包括文件ID，struct File以及struct Fd。JOS同时打开的文件数一共为 MAXOPEN(1024) 个。

	```
	struct OpenFile {                                                              
	    uint32_t o_fileid;  // file id                                             
	    struct File *o_file;    // mapped descriptor for open file                 
	    int o_mode;     // open mode                                               
	    struct Fd *o_fd;    // Fd page                                             
	};    
	
	struct Fd {
	    int fd_dev_id;
	    off_t fd_offset;
	    int fd_omode;
	    union {
	        // File server files
	        struct FdFile fd_file;
	    };  
	}; 
	```

文件操作函数如下：

- file_block_walk(struct File *f, uint32_t filebno, uint32_t **ppdiskbno, bool alloc)

	这个函数是查找文件第filebno块的数据块的地址，查到的地址存储在 ppdiskbno 中。注意这里要检查间接块，如果alloc为1且寻址的块号>=NDIRECT，而间接块没有分配的话需要分配一个间接块。

- file_get_block(struct File *f, uint32_t filebno, char **blk)

	查找文件第filebno块的块地址，并将块地址在虚拟内存中映射的地址存储在 blk 中(即将diskaddr(blockno)存到blk中)。

- dir_lookup(struct File *dir, const char *name, struct File **file)

	在目录dir中查找名为name的文件，如果找到了设置*file为找到的文件。因为目录的数据块存储的是struct File列表，可以据此来查找文件。

- file_open(const char *path, struct File **pf)

	打开文件，设置*pf为查找到的文件指针。
	
- file_create(const char *path, struct File **pf)
	创建路径/文件，在*pf存储创建好的文件指针。

- file_read(struct File *f, void *buf, size_t count, off_t offset) 

	从文件的offset处开始读取count个字节到buf中，返回实际读取的字节数。

- file_write(struct File *f, const void *buf, size_t count, off_t offset) 

	从文件offset处开始写入buf中的count字节，返回实际写入的字节数。

## 2.5 文件系统接口
完成了基本函数后，现在可以通过IPC来实现JOS的文件系统操作了。流程图如下所示：

```
 Regular env           FS env
   +---------------+   +---------------+
   |      read     |   |   file_read   |
   |   (lib/fd.c)  |   |   (fs/fs.c)   |
...|.......|.......|...|.......^.......|...............
   |       v       |   |       |       | RPC mechanism
   |  devfile_read |   |  serve_read   |
   |  (lib/file.c) |   |  (fs/serv.c)  |
   |       |       |   |       ^       |
   |       v       |   |       |       |
   |     fsipc     |   |     serve     |
   |  (lib/file.c) |   |  (fs/serv.c)  |
   |       |       |   |       ^       |
   |       v       |   |       |       |
   |   ipc_send    |   |   ipc_recv    |
   |       |       |   |       ^       |
   +-------|-------+   +-------|-------+
           |                   |
           +-------------------+
```

写文件过程类似，流程是`devfile_write -> serve_write -> file_write`。这里分析几个例子看下JOS读写文件流程：

#### 直接读文件
这里跳过文件描述符层，直接打开文件并读取

```
if ((r = xopen("/not-found", O_RDONLY)) < 0 && r != -E_NOT_FOUND)
    panic("serve_open /not-found: %e", r); 
else if (r >= 0)
    panic("serve_open /not-found succeeded!");

if ((r = xopen("/newmotd", O_RDONLY)) < 0)
    panic("serve_open /newmotd: %e", r); 
if (FVA->fd_dev_id != 'f' || FVA->fd_offset != 0 || FVA->fd_omode != O_RDONLY)
    panic("serve_open did not fill struct Fd correctly\n");
cprintf("serve_open is good\n");
    
memset(buf, 0, sizeof buf);
if ((r = devfile.dev_read(FVA, buf, sizeof buf)) < 0)
    panic("file_read: %e", r); 
if (strcmp(buf, msg) != 0)
    panic("file_read returned wrong data");
cprintf("file_read is good\n");
```

- 1) fs 进程首先调用 serve_init 完成opentab的初始化，然后在 地址 0x0ffff000 处 接收IPC的页。
- 2）测试进程通过 IPC 发送FSREQ_OPEN请求，请求参数在 fsipcbuf所在页中，然后在 FVA (0xCCCCC000)处接收fs进程的IPC页。
- 3）fs进程的serve() 接收到 FSREQ_OPEN 请求，调用 serve_open() 处理该请求。会先分配一个OpenFile结构给文件，设置o_file为文件指针，o_fd为文件描述符等，IPC映射的页的权限为 PTE_SHARE 等，然后将文件描述符所在的页作为参数发送IPC请求给测试进程。
- 4) 测试进程在 FVA 处读取打开的文件描述符信息，然后返回。

#### 直接读取文件
- 1）调用devfile_read发送fsipc到文件系统进程。
- 2）fs进程通过ipc_recv接收fsipc请求，然后传给serve函数处理。serve函数根据fspic请求类型，调用 serve_read 处理请求。
- 3）fs系统进程最终通过 file_read 完成文件读取。文件读取结果存储到了fsipcbuf中的readRet中，恰好是一页的大小，而且这个是测试进程一开始就映射了的页面，可以直接读取。

#### 直接写入文件
与读取文件类似，只是不用返回读取结果了，在IPC中返回写入字节数即可。路径是`serve()->serve_write()->devfile_write()->file_write()`

#### 通过文件描述符打开/读取/写入文件
- 通过文件描述符打开文件时，测试进程会先通过 fd_alloc() 分配一个文件描述符，然后在文件描述符fd 处接收fs进程的IPC页，分配的fd的地址为 (0xD0000000 + i * PGSIZE)。后面的流程跟之前直接操作类似。
- 通过文件描述符读取写入文件，会先通过 fd_lookup() 找到文件描述符对应的文件信息，然后再根据设备类型调用相应的读写操作。如文件就是 devfile_read/devfile_write，console就是devcons_read/devcons_write。

# 3 Spawning 进程
spawn代码用于创建一个子进程，然后从磁盘中加载一个程序代码镜像并在子进程运行加载的程序。这有点类似Unix的fork+exec，但是又有所不同，因为我们的spawn进程运行在用户空间，我们通过一个新的系统调用 `sys_env_set_trapframe`简化了一些操作。

在fork和spawn中，JOS需要实现文件描述符的共享，这里引入了一个新的 PTE_SHARE 标识，用于标识共享页，这样在拷贝时可以进行统一处理，不再类似fork那样用COW，而是直接共享。因为用fork的话，如子进程修改了文件数据，此时会新分配一个页来保存修改数据，而父进程里面对应页面是没有变化的，这样无法在父子进程共享文件的变化。

spawn的流程如下：

- 打开文件，获取文件描述符fd。
- 读取ELF头部，检查ELF文件魔数。
- 调用 sys_exofork() 创建一个子进程。
- child_tf 设置，主要是设置了eip为ELF文件的入口点e_entry，设置esp为init_stack()分配的栈空间。
- 最后将 ELF 文件映射到子进程的地址空间，并根据ELF的读写段来设置读写权限。
- 拷贝共享的页。
- 调用sys_env_set_trapframe()设置子进程的env_tf位child_tf。
- 调用 sys_env_set_status() 设置子进程为RUNNABLE状态。

**看过之前实验的朋友可能发现了，我之前的fork在duppage时拷贝代码空间是以程序代码的 end 为结束的，现在看来这是有问题的，因为文件系统映射的地址并不在其中，需要将end改为 USTACKTOP-PGSIZE。此外，在duppage和spawn.c中的copy_shared_pages中要对 PTE_SHARE 做处理，直接映射即可，权限要用 PTE_SYSCALL，因为文件系统相关的页权限都是用的PTE_SYSCALL，否则会检查失败。**

# 4 键盘接口
用户键盘输入会产生键盘中断IRQ_KBD(通过QEMU图形界面输入触发)或者串口中断IRQ_SERIAL(通过console触发)，为此要在trap.c中处理这两个中断，分别调用 kbd_intr() 和 serial_intr() 即可。

这里有个地方注意下，测试进程 `user/testkbd.c` 中用的是 readline() 来读取用户输入的，它的流程如下：

```
readline() -> lib/console.c getchar() -> read() -> devcons_read() 
           -> lib/syscall.c sys_cgetc() -> kern/syscall.c sys_cgetc()
           -> kern/console.c cons_getc()
```

其实在cons_getc()中调用了 kbd_intr() 和 serial_intr() 这两个函数，因此在我们之前的实验内核的 monitor 中已经屏蔽了中断，一样可以读取到键盘输入。

# 5 Shell
JOS的Shell实现了管道，IO重定向等功能，具体实现在 user/sh.c 中，在`make run-icode`后，我们可以运行下面的代码来测试：

```
echo hello world | cat
cat lorem |cat
cat lorem |num
cat lorem |num |num |num |num |num
lsfd
```

这里有几个小程序如cat，echo等，管道和IO重定向具体实现如下：

### 输入/输出重定向
输入重定向：跟Linux一样，使用 < 语法。实现原理就是使用 dup(fd，0) 将文件描述符拷贝到标准输入0，然后关闭fd，最后从标准输入中读取文件内容即可。如 `cat < script`便是先将script文件重定向到标准输入0，最后spawn执行cat从标准输入读取内容并输出到标准输出。而如果使用 `sh < script`，又是不同的，此时spawn进程执行的是sh进程，它会先读取script文件内容，然后对script文件内容一行行命令spawn执行。

输出重定向：使用 > 语法。实现原理就是使用 dup(fd, 1)将文件描述符拷贝到标准输出1，然后关闭fd，这样输出到标准输出就相当于输出到文件了。如 `echo haha > motd`，会将motd文件内容改为 haha。

### 管道
JOS管道实现在`lib/pipe.c`，它分配两个文件描述符作为管道输入输出端，设备类型为管道，对应的数据页部分映射到了同样的物理页，只是设置的文件描述符的权限不同，pipe[0]对应的文件描述符为只读，而pipe[1]可写。然后fork()创建一个子进程，子进程中将 pipe[0] 拷贝到标准输入，然后重新读取输入运行管道右边的命令。父进程中则是将 pipe[1] 拷贝到标准输出。父进程会先 spawn运行左边命令，输出会重定向到标准输出，即pipe[1]这个fd。而子进程接着从标准输入读取输入，也就是从pipe[0]这个fd读取输入，然后输出结果。管道读写使用方法是 devpipe_read和devpipe_write，如果管道没有数据可读，则会sys_yield() 调度其他进程先运行。

如运行命令 `echo haha|cat`，则先父进程先spawn一个进程运行 `echo haha`，并将输出`haha`重定向到 pipe[1]，而子进程接着spawn一个进程运行 `cat`，它从pipe[0]读取输入，而因为 pipe[0] 和 pipe[1] 映射的是同样的物理页面，所以可以读取到pipe[1]中的内容，从而实现了管道功能。



