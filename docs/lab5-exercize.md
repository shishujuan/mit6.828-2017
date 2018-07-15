# Exercize 1
为文件系统进程添加IO权限，添加代码如下，作业1完成后，可以通过`fs i/o`测试。

```
@@ -396,6 +396,9 @@ env_create(uint8_t *binary, enum EnvType type)
        // LAB 5: Your code here.
        struct Env *e;
        env_alloc(&e, 0);
+       if (type == ENV_TYPE_FS) {
+               e->env_tf.tf_eflags |= FL_IOPL_MASK;
+       }
        e->env_type = type;
        load_icode(e, binary);
 }
```

## Question 1
不需要做额外处理。因为不同进程有自己的Trapframe，互不影响。

# Exercize 2
实现 `fs/bc.c` 中的 bc_pgfault 和 flush_block。注意这里flush_block中的sys_page_map使用的权限用 PTE_SYSCALL。作业2完成后，需要能通过 `"check_bc", "check_super", "check_bitmap"` 这三个测试。

```
--- a/fs/bc.c
+++ b/fs/bc.c
@@ -48,6 +48,13 @@ bc_pgfault(struct UTrapframe *utf)
        // the disk.
        //
        // LAB 5: you code here:
+       cprintf("bc pgfault block:%d, bitmap:%x\n", blockno, bitmap);
+
+       addr = (void *)ROUNDDOWN(addr, PGSIZE);
+       if ((r = sys_page_alloc(0, addr, PTE_W|PTE_U|PTE_P)))
+               panic("in bc_pgfault, sys_page_alloc: %e", r);
+
+       ide_read(blockno*BLKSECTS, addr, BLKSECTS);
 
        // Clear the dirty bit for the disk block page since we just read the
        // block from disk
@@ -77,7 +84,17 @@ flush_block(void *addr)
                panic("flush_block of bad va %08x", addr);
 
        // LAB 5: Your code here.
-       panic("flush_block not implemented");
+       // panic("flush_block not implemented");
+       if (!va_is_mapped(addr) || !va_is_dirty(addr)) return;
+
+       addr = (void *)ROUNDDOWN(addr, PGSIZE);
+       ide_write(blockno*BLKSECTS, addr, BLKSECTS);
+       int r;
+       if ((r = sys_page_map(0, addr, 0, addr, uvpt[PGNUM(addr)] & PTE_SYSCALL)) < 0)
+               panic("in bc_pgfault, sys_page_map: %e", r);
+
+
+
 }
```

# Exercize 3-4
完成 alloc_block，file_block_walk以及file_get_block。作业3，4完成后，需要通过 `"alloc_block"，"file_open", "file_get_block", "file_flush/file_truncated/file rewrite", "testfile"`。

```
index 45ecaf8..7571b09 100644
--- a/fs/fs.c
+++ b/fs/fs.c
@@ -62,7 +62,17 @@ alloc_block(void)
        // super->s_nblocks blocks in the disk altogether.
 
        // LAB 5: Your code here.
-       panic("alloc_block not implemented");
+       // panic("alloc_block not implemented");
+       // skip boot block, super block, bitmap block.
+       int i;
+       for (i = 3; i < super->s_nblocks; i++) {
+               if (block_is_free(i)) {
+                       bitmap[i/32] &= ~(1<<(i % 32));
+                       flush_block(diskaddr(i));
+                       cprintf("alloc block:%d\n", i);
+                       return i;
+               }
+       }
        return -E_NO_DISK;
 }
 
@@ -134,8 +144,29 @@ fs_init(void)
 static int
 file_block_walk(struct File *f, uint32_t filebno, uint32_t **ppdiskbno, bool alloc)
 {
-       // LAB 5: Your code here.
-       panic("file_block_walk not implemented");
+       // LAB 5: Your code here.
+       // panic("file_block_walk not implemented");
+       if (filebno >= NDIRECT + NINDIRECT)
+               return -E_INVAL;
+
+       if (filebno < NDIRECT) {
+               *ppdiskbno = f->f_direct + filebno;
+       } else {
+               if (!f->f_indirect) {
+                       if (alloc) {
+                               int blockno = alloc_block();
+                               if (blockno < 0)
+                                       return -E_NO_DISK;
+
+                               memset(diskaddr(blockno), 0, BLKSIZE);
+                               f->f_indirect = blockno;
+                       } else {
+                               return -E_NOT_FOUND;
+                       }
+               }
+               *ppdiskbno = (uint32_t *)diskaddr(f->f_indirect) + (filebno-NDIRECT);
+       }
+       return 0;
 }
 
 // Set *blk to the address in memory where the filebno'th
@@ -150,7 +181,22 @@ int
 file_get_block(struct File *f, uint32_t filebno, char **blk)
 {
        // LAB 5: Your code here.
-       panic("file_get_block not implemented");
+       // panic("file_get_block not implemented");
+       uint32_t *ppdiskbno;
+       int r;
+       if ((r = file_block_walk(f, filebno, &ppdiskbno, 1)) < 0)
+               return r;
+
+       if (*ppdiskbno == 0) {
+               int blockno = alloc_block();
+               if (blockno < 0)
+                       return -E_NO_DISK;
+
+               memset(diskaddr(blockno), 0, BLKSIZE);
+               *ppdiskbno = blockno;
+       }
+       *blk = diskaddr(*ppdiskbno);
+       return 0;
 }
```

# Exercize 5-6
完成 serve_read 和 serve_write以及devfile_write函数。完成后，可以通过 `serve_open/file_stat/file_close"，"file_read"，"file_write", "file_read after file_write", "open", "large file"`，可得 90/150。

```
diff --git a/fs/serv.c b/fs/serv.c
index 76c1d99..508907e 100644
--- a/fs/serv.c
+++ b/fs/serv.c
@@ -214,7 +214,18 @@ serve_read(envid_t envid, union Fsipc *ipc)
                cprintf("serve_read %08x %08x %08x\n", envid, req->req_fileid, req->req_n);
 
        // Lab 5: Your code here:
-       return 0;
+       struct OpenFile *o;
+       int r;
+       if ((r = openfile_lookup(envid, req->req_fileid, &o)) < 0) {
+               return r;
+       }
+
+       r = file_read(o->o_file, ret->ret_buf, req->req_n, o->o_fd->fd_offset);
+       if (r < 0)
+               return r;
+
+       o->o_fd->fd_offset += r;
+       return r;
 }
 
 
@@ -229,7 +240,18 @@ serve_write(envid_t envid, struct Fsreq_write *req)
                cprintf("serve_write %08x %08x %08x\n", envid, req->req_fileid, req->req_n);
 
        // LAB 5: Your code here.
-       panic("serve_write not implemented");
+       // panic("serve_write not implemented");
+       struct OpenFile *o;
+       int r;
+       if ((r = openfile_lookup(envid, req->req_fileid, &o) < 0))
+               return r;
+
+       r = file_write(o->o_file, req->req_buf, req->req_n, o->o_fd->fd_offset);
+       if (r < 0)
+               return r;
+
+       o->o_fd->fd_offset += r;
+       return r;
 }
 
 // Stat ipc->stat.req_fileid.  Return the file's struct Stat to the
diff --git a/lib/file.c b/lib/file.c
index 39025b2..0ade71b 100644
--- a/lib/file.c
+++ b/lib/file.c
@@ -141,7 +141,12 @@ devfile_write(struct Fd *fd, const void *buf, size_t n)
        // remember that write is always allowed to write *fewer*
        // bytes than requested.
        // LAB 5: Your code here
-       panic("devfile_write not implemented");
+       // panic("devfile_write not implemented");
+       fsipcbuf.write.req_fileid = fd->fd_file.id;
+       fsipcbuf.write.req_n = MIN(n, PGSIZE);
+       memmove(fsipcbuf.write.req_buf, buf, fsipcbuf.write.req_n);
+       int r = fsipc(FSREQ_WRITE, NULL);
+       return r;
 }
```

# Exercize 7
完成 sys_env_set_trapframe()。

```
diff --git a/kern/syscall.c b/kern/syscall.c
index 9538fb7..90fc6cc 100644
--- a/kern/syscall.c
+++ b/kern/syscall.c
@@ -132,7 +132,16 @@ sys_env_set_trapframe(envid_t envid, struct Trapframe *tf)
        // LAB 5: Your code here.
        // Remember to check whether the user has supplied us with a good
        // address!
-       panic("sys_env_set_trapframe not implemented");
+       // panic("sys_env_set_trapframe not implemented");
+       struct Env *e;
+       if (envid2env(envid, &e, 1)) {
+               return -E_BAD_ENV;
+       }
+
+       e->env_tf = *tf;
+       e->env_tf.tf_eflags |= FL_IF;
+       e->env_tf.tf_eflags &= ~FL_IOPL_MASK;
+       return 0;
 }
 
 // Set the page fault upcall for 'envid' by modifying the corresponding struct
@@ -417,6 +426,8 @@ syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
                return sys_ipc_try_send(a1, a2, (void *)a3, a4);
        case SYS_ipc_recv:
                return sys_ipc_recv((void *)a1);
+       case SYS_env_set_trapframe:
+               return sys_env_set_trapframe(a1, (struct Trapframe *)a2);
        default:
                return -E_INVAL;
        }
```

# Exercize 8
修改 `lib/fork.c` 和 `lib/spawn.c`，支持共享页面。这里修复之前映射的一个问题，之前是以进程end作为映射结束位置，为了支持文件系统，改成 USTACKTOP-PGSIZE。

```
diff --git a/lib/fork.c b/lib/fork.c
index 74e35db..8a62f27 100644
--- a/lib/fork.c
+++ b/lib/fork.c
@@ -71,7 +71,11 @@ duppage(envid_t envid, unsigned pn)
        // LAB 4: Your code here.
        void *addr = (void *)(pn * PGSIZE);
-       if (uvpt[pn] & (PTE_W|PTE_COW)) {
+       if (uvpt[pn] & PTE_SHARE) {
+               if ((r = sys_page_map(0, addr, envid, addr, PTE_SYSCALL)) < 0)
+                       panic("duppage sys_page_map:%e", r);
+       } else if (uvpt[pn] & (PTE_W|PTE_COW)) {
                if ((r = sys_page_map(0, addr, envid, addr, PTE_COW|PTE_U|PTE_P)) < 0)
                        panic("sys_page_map COW:%e", r);
 
@@ -116,8 +120,7 @@ fork(void)
                return 0;
        }
 
-       extern unsigned char end[];
-       for (addr = (uint8_t *)UTEXT; addr < end; addr += PGSIZE) {
+       for (addr = (uint8_t *)UTEXT; addr < (uint8_t *)USTACKTOP-PGSIZE; addr += PGSIZE) {
                if ((uvpd[PDX(addr)] & PTE_P) && (uvpt[PGNUM(addr)] & PTE_P)
                                && (uvpt[PGNUM(addr)] & PTE_U)) {
                        duppage(envid, PGNUM(addr));
diff --git a/lib/spawn.c b/lib/spawn.c
index 9d0eb07..fa2c8d2 100644
--- a/lib/spawn.c
+++ b/lib/spawn.c
@@ -302,6 +302,14 @@ static int
 copy_shared_pages(envid_t child)
 {
        // LAB 5: Your code here.
+       uintptr_t addr;
+       for (addr = 0; addr < UTOP; addr += PGSIZE) {
+               if ((uvpd[PDX(addr)] & PTE_P) && (uvpt[PGNUM(addr)] & PTE_P) &&
+                               (uvpt[PGNUM(addr)] & PTE_U) && (uvpt[PGNUM(addr)] & PTE_SHARE)) {
+                       cprintf("copy shared page %d to env:%x\n", PGNUM(addr), child);
+            sys_page_map(0, (void*)addr, child, (void*)addr, (uvpt[PGNUM(addr)] & PTE_SYSCALL));
+        }
+       }
        return 0;
 }
```

# Exercize 9
处理键盘和串口中断，这里即便去掉 kbd_intr() 和 serial_intr() 也不会有影响，因为cons_getc()有调用它们。

```
diff --git a/kern/trap.c b/kern/trap.c
index 1af658b..bc50613 100644
--- a/kern/trap.c
+++ b/kern/trap.c
@@ -274,6 +274,15 @@ trap_dispatch(struct Trapframe *tf)
 
        // Handle keyboard and serial interrupts.
        // LAB 5: Your code here.
+       if (tf->tf_trapno == IRQ_OFFSET + IRQ_KBD) {
+               kbd_intr();
+               return;
+       }
+
+       if (tf->tf_trapno == IRQ_OFFSET + IRQ_SERIAL) {
+               serial_intr();
+               return;
+       }
 
        // Unexpected trap: The user process or the kernel has a bug.
        print_trapframe(tf);
```

# Exercize 10
修改 `user/sh.c` 支持输入重定向，参照输出重定向修改即可。

```
diff --git a/user/sh.c b/user/sh.c
index 26f501a..387a422 100644
--- a/user/sh.c
+++ b/user/sh.c
@@ -55,7 +55,15 @@ again:
                        // then close the original 'fd'.
 
                        // LAB 5: Your code here.
-                       panic("< redirection not implemented");
+                       // panic("< redirection not implemented");
+                       if ((fd = open(t, O_RDONLY)) < 0) {
+                               cprintf("open %s for read: %e", t, fd);
+                               exit();
+                       }
+                       if (fd != 0) {
+                               dup(fd, 0);
+                               close(fd);
+                       }
                        break;
```
