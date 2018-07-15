# Exercize 1
在 kern/trap.c 中针对每次时钟中断调用`time_tick`。实现系统调用 `sys_time_msec`。

```
diff --git a/kern/syscall.c b/kern/syscall.c
index d45e337..72b120b 100644
--- a/kern/syscall.c
+++ b/kern/syscall.c
@@ -393,7 +393,8 @@ static int
 sys_time_msec(void)
 {
        // LAB 6: Your code here.
-       panic("sys_time_msec not implemented");
+       // panic("sys_time_msec not implemented");
+       return time_msec();
 }
 
 // Dispatches to the correct kernel function, passing the arguments.
@@ -437,6 +438,8 @@ syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
                return sys_ipc_recv((void *)a1);
        case SYS_env_set_trapframe:
                return sys_env_set_trapframe(a1, (struct Trapframe *)a2);
+       case SYS_time_msec:
+               return sys_time_msec();
        default:
                return -E_INVAL;
        }
diff --git a/kern/trap.c b/kern/trap.c
index a834130..95df035 100644
--- a/kern/trap.c
+++ b/kern/trap.c
@@ -267,8 +267,9 @@ trap_dispatch(struct Trapframe *tf)
        // interrupt using lapic_eoi() before calling the scheduler!
        // LAB 4: Your code here.
        if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
-               // cprintf("irq timer\n");
                lapic_eoi();
+               if (thiscpu->cpu_id == 0)
+                       time_tick();
                sched_yield();
                return;
        }
```
测试`make INIT_CFLAGS=-DTEST_NO_NS run-testtime`，看到输出如下则说明功能正常。

```
starting count down: 5 4 3 2 1 0 
```

# Exercize 2
阅读Intel的[E1000网卡相关文档](https://pdos.csail.mit.edu/6.828/2017/readings/hardware/8254x_GBe_SDM.pdf)。

# Exercize 3
初始化E1000网卡。

```
diff --git a/kern/e1000.c b/kern/e1000.c
index 7570e75..901a19f 100644
--- a/kern/e1000.c
+++ b/kern/e1000.c
@@ -1,3 +1,11 @@
 #include <kern/e1000.h>
+#include <kern/pmap.h>
 
 // LAB 6: Your driver code here
+int
+e1000_attachfn(struct pci_func *pcif)
+{
+       pci_func_enable(pcif);
+       cprintf("reg_base:%x, reg_size:%x\n", pcif->reg_base[0], pcif->reg_size[0]);
+       return 0;
+}
diff --git a/kern/e1000.h b/kern/e1000.h
index e563ac4..78c0355 100644
--- a/kern/e1000.h
+++ b/kern/e1000.h
@@ -1,4 +1,11 @@
 #ifndef JOS_KERN_E1000_H
 #define JOS_KERN_E1000_H
 
+#include "kern/pci.h"
+
+#define E1000_VENDER_ID_82540EM 0x8086
+#define E1000_DEV_ID_82540EM 0x100E
+
+int e1000_attachfn(struct pci_func *pcif);
+
 #endif // JOS_KERN_E1000_H
diff --git a/kern/pci.c b/kern/pci.c
index 784e072..7e4acf3 100644
--- a/kern/pci.c
+++ b/kern/pci.c
@@ -31,6 +31,7 @@ struct pci_driver pci_attach_class[] = {
 // pci_attach_vendor matches the vendor ID and device ID of a PCI device. key1
 // and key2 should be the vendor ID and device ID respectively
 struct pci_driver pci_attach_vendor[] = {
+       { E1000_VENDER_ID_82540EM, E1000_DEV_ID_82540EM, &e1000_attachfn },
        { 0, 0, 0 },
 };
```
如果实现正确，运行`make grade`可以看到测试pci attach通过。

```
pci attach: OK (1.6s) 
```

# Exercize 4
添加网卡的BAR 0的mmio映射。用到之前实验实现的 mmio_map_region 函数。

```
diff --git a/kern/e1000.c b/kern/e1000.c
index 901a19f..0e5de3b 100644
--- a/kern/e1000.c
+++ b/kern/e1000.c
@@ -2,10 +2,20 @@
 #include <kern/pmap.h>
 
 // LAB 6: Your driver code here
+volatile void *bar_va;
+
+#define E1000REG(offset) (void *)(bar_va + offset)
+
+
 int
 e1000_attachfn(struct pci_func *pcif)
 {
        pci_func_enable(pcif);
        cprintf("reg_base:%x, reg_size:%x\n", pcif->reg_base[0], pcif->reg_size[0]);
+
+       bar_va = mmio_map_region(pcif->reg_base[0], pcif->reg_size[0]);
+
+       uint32_t *status_reg = (uint32_t *)E1000REG(E1000_STATUS);
+       assert(*status_reg == 0x80080783);
        return 0;
 }
diff --git a/kern/e1000.h b/kern/e1000.h
index 78c0355..30e9e73 100644
--- a/kern/e1000.h
+++ b/kern/e1000.h
@@ -6,6 +6,8 @@
 #define E1000_VENDER_ID_82540EM 0x8086
 #define E1000_DEV_ID_82540EM 0x100E
 
+#define E1000_STATUS   0x00008  /* Device Status - RO */
+
 int e1000_attachfn(struct pci_func *pcif);
 
 #endif // JOS_KERN_E1000_H
```

# Exercize 5
完成网卡传输描述符队列初始化。初始化正确的话运行` make E1000_DEBUG=TXERR,TX qemu` 应该会看到这个消息 `e1000: tx disabled`，代码如下：

```
diff --git a/kern/e1000.c b/kern/e1000.c
index f874bf5..5a0d8b3 100644
--- a/kern/e1000.c
+++ b/kern/e1000.c
@@ -5,6 +5,10 @@
 volatile void *bar_va;
 #define E1000REG(offset) (void *)(bar_va + offset)
 
+struct e1000_tdh *tdh;
+struct e1000_tdt *tdt;
+struct e1000_tx_desc tx_desc_array[TXDESCS];
+char tx_buffer_array[TXDESCS][TX_PKT_SIZE];
 
 int
 e1000_attachfn(struct pci_func *pcif)
@@ -16,5 +20,44 @@ e1000_attachfn(struct pci_func *pcif)
 
        uint32_t *status_reg = (uint32_t *)E1000REG(E1000_STATUS);
        assert(*status_reg == 0x80080783);
+
+       e1000_transmit_init();
        return 0;
 }
+
+static void
+e1000_transmit_init()
+{
+       int i;
+       for (i = 0; i < TXDESCS; i++) {
+               tx_desc_array[i].addr = PADDR(tx_buffer_array[i]);
+               tx_desc_array[i].cmd = 0;
+               tx_desc_array[i].status |= E1000_TXD_STAT_DD;
+       }
+
+       struct e1000_tdlen *tdlen = (struct e1000_tdlen *)E1000REG(E1000_TDLEN);
+       tdlen->len = TXDESCS;
+
+       uint32_t *tdbal = (uint32_t *)E1000REG(E1000_TDBAL);
+       *tdbal = PADDR(tx_desc_array);
+
+       uint32_t *tdbah = (uint32_t *)E1000REG(E1000_TDBAH);
+       *tdbah = 0;
+
+       tdh = (struct e1000_tdh *)E1000REG(E1000_TDH);
+       tdh->tdh = 0;
+
+       tdt = (struct e1000_tdt *)E1000REG(E1000_TDT);
+       tdt->tdt = 0;
+
+       struct e1000_tctl *tctl = (struct e1000_tctl *)E1000REG(E1000_TCTL);
+       tctl->en = 1;
+       tctl->psp = 1;
+       tctl->ct = 0x10;
+       tctl->cold = 0x40;
+
+       struct e1000_tipg *tipg = (struct e1000_tipg *)E1000REG(E1000_TIPG);
+       tipg->ipgt = 10;
+       tipg->ipgr1 = 4;
+       tipg->ipgr2 = 6;
+}
diff --git a/kern/e1000.h b/kern/e1000.h
index 30e9e73..b62febf 100644
--- a/kern/e1000.h
+++ b/kern/e1000.h
@@ -6,8 +6,73 @@
 #define E1000_VENDER_ID_82540EM 0x8086
 #define E1000_DEV_ID_82540EM 0x100E
 
+#define TXDESCS 32
+#define TX_PKT_SIZE 1518
+
 #define E1000_STATUS   0x00008  /* Device Status - RO */
+#define E1000_TCTL     0x00400  /* TX Control - RW */
+#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */
+#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
+#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
+#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
+#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
+#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */
+#define E1000_TXD_STAT_DD    0x00000001 /* Descriptor Done */
+#define E1000_TXD_CMD_EOP    0x00000001 /* End of Packet */
+#define E1000_TXD_CMD_RS     0x00000008 /* Report Status */
+
+
+/*transmit descriptor related*/
+struct e1000_tx_desc
+{
+       uint64_t addr;
+       uint16_t length;
+       uint8_t cso;
+       uint8_t cmd;
+       uint8_t status;
+       uint8_t css;
+       uint16_t special;
+}__attribute__((packed));
+
+struct e1000_tctl {
+       uint32_t rsv1:   1;
+       uint32_t en:     1;
+       uint32_t rsv2:   1;
+       uint32_t psp:    1;
+       uint32_t ct:     8;
+       uint32_t cold:   10;
+       uint32_t swxoff: 1;
+       uint32_t rsv3:   1;
+       uint32_t rtlc:   1;
+       uint32_t nrtu:   1;
+       uint32_t rsv4:   6;
+};
+
+struct e1000_tipg {
+       uint32_t ipgt:   10;
+       uint32_t ipgr1:  10;
+       uint32_t ipgr2:  10;
+       uint32_t rsv:    2;
+};
+
+struct e1000_tdt {
+       uint16_t tdt;
+       uint16_t rsv;
+};
+
+struct e1000_tdlen {
+       uint32_t zero: 7;
+       uint32_t len:  13;
+       uint32_t rsv:  12;
+};
+
+struct e1000_tdh {
+       uint16_t tdh;
+       uint16_t rsv;
+};
+
 
 int e1000_attachfn(struct pci_func *pcif);
+static void e1000_transmit_init();
 
 #endif // JOS_KERN_E1000_H
```

# Exercize 6
实现发送数据包到网卡功能。实现完成后，这里在transmit_attachfn 中加入测试代码直接测试发送数据包功能。运行`make E1000_DEBUG=TXERR,TX qemu`，正确实现了的话应该看到类似这样的输出`e1000: index 0: 0x301040 : 900000d 0`。

```
diff --git a/kern/e1000.c b/kern/e1000.c
index 5a0d8b3..2d488f2 100644
--- a/kern/e1000.c
+++ b/kern/e1000.c
@@ -1,5 +1,6 @@
 #include <kern/e1000.h>
 #include <kern/pmap.h>
+#include <inc/string.h>
 
 // LAB 6: Your driver code here
 volatile void *bar_va;
@@ -22,6 +23,13 @@ e1000_attachfn(struct pci_func *pcif)
        assert(*status_reg == 0x80080783);
 
        e1000_transmit_init();
+
+       /*
+        * transmit test
+        */
+       char *data = "transmit test";
+       e1000_transmit(data, 13);
+
        return 0;
 }
 
@@ -61,3 +69,19 @@ e1000_transmit_init()
        tipg->ipgr1 = 4;
        tipg->ipgr2 = 6;
 }
+
+int
+e1000_transmit(void *data, size_t len)
+{
+       uint32_t current = tdt->tdt;
+       if(!(tx_desc_array[current].status & E1000_TXD_STAT_DD)) {
+               return -E_TRANSMIT_RETRY;
+       }
+       tx_desc_array[current].length = len;
+       tx_desc_array[current].status &= ~E1000_TXD_STAT_DD;
+       tx_desc_array[current].cmd |= (E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS);
+       memcpy(tx_buffer_array[current], data, len);
+       uint32_t next = (current + 1) % TXDESCS;
+       tdt->tdt = next;
+       return 0;
+}
diff --git a/kern/e1000.h b/kern/e1000.h
index b62febf..02767c3 100644
--- a/kern/e1000.h
+++ b/kern/e1000.h
@@ -21,6 +21,10 @@
 #define E1000_TXD_CMD_EOP    0x00000001 /* End of Packet */
 #define E1000_TXD_CMD_RS     0x00000008 /* Report Status */
 
+enum {
+       E_TRANSMIT_RETRY = 1,
+};
+
 
 /*transmit descriptor related*/
 struct e1000_tx_desc
@@ -74,5 +78,6 @@ struct e1000_tdh {
 
 int e1000_attachfn(struct pci_func *pcif);
 static void e1000_transmit_init();
+int e1000_transmit(void *data, size_t len);
 
 #endif // JOS_KERN_E1000_H
```

# Exercize 7
添加发送数据包的系统调用。

```
diff --git a/inc/lib.h b/inc/lib.h
index 66740e8..956c678 100644
--- a/inc/lib.h
+++ b/inc/lib.h
@@ -60,6 +60,7 @@ int   sys_page_unmap(envid_t env, void *pg);
 int    sys_ipc_try_send(envid_t to_env, uint32_t value, void *pg, int perm);
 int    sys_ipc_recv(void *rcv_pg);
 unsigned int sys_time_msec(void);
+int sys_pkt_send(void *addr, size_t len);
 
 // This must be inlined.  Exercise for reader: why?
 static inline envid_t __attribute__((always_inline))
diff --git a/inc/syscall.h b/inc/syscall.h
index 36f26de..b2317cf 100644
--- a/inc/syscall.h
+++ b/inc/syscall.h
@@ -18,6 +18,7 @@ enum {
        SYS_ipc_try_send,
        SYS_ipc_recv,
        SYS_time_msec,
+       SYS_pkt_send,
        NSYSCALLS
 };
 
diff --git a/kern/syscall.c b/kern/syscall.c
index 72b120b..bc999a2 100644
--- a/kern/syscall.c
+++ b/kern/syscall.c
@@ -12,6 +12,7 @@
 #include <kern/console.h>
 #include <kern/sched.h>
 #include <kern/time.h>
+#include <kern/e1000.h>
 
 // Print a string to the system console.
 // The string is exactly 'len' characters long.
@@ -397,6 +398,12 @@ sys_time_msec(void)
        return time_msec();
 }
 
+
+static int 
+sys_pkt_send(void *data, int len)
+{
+       return e1000_transmit(data, len);
+}
+
 // Dispatches to the correct kernel function, passing the arguments.
 int32_t
 syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
@@ -440,6 +447,8 @@ syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
                return sys_env_set_trapframe(a1, (struct Trapframe *)a2);
        case SYS_time_msec:
                return sys_time_msec();
+       case SYS_pkt_send:
+               return sys_pkt_send((void *)a1, a2);
        default:
                return -E_INVAL;
        }
        
diff --git a/lib/syscall.c b/lib/syscall.c
index 9e1a1d9..bd3a31b 100644
--- a/lib/syscall.c
+++ b/lib/syscall.c
@@ -122,3 +122,9 @@ sys_time_msec(void)
 {
        return (unsigned int) syscall(SYS_time_msec, 0, 0, 0, 0, 0, 0);
 }
+
+int
+sys_pkt_send(void *data, size_t len)
+{
+       return syscall(SYS_pkt_send, 1, (uint32_t)data, len, 0, 0, 0);
+}
```

# Exercize 8

完成`net/output.c`中的output()函数，注意把之前的测试发送数据包的代码去掉。

```
diff --git a/kern/e1000.c b/kern/e1000.c
index 2d488f2..db2941b 100644
--- a/kern/e1000.c
+++ b/kern/e1000.c
@@ -27,8 +27,8 @@ e1000_attachfn(struct pci_func *pcif)
        /*
         * transmit test
         */
-       char *data = "transmit test";
-       e1000_transmit(data, 13);
+       // char *data = "transmit test";
+       // e1000_transmit(data, 13);
 
        return 0;
 }
diff --git a/net/output.c b/net/output.c
index f577c4e..1030735 100644
--- a/net/output.c
+++ b/net/output.c
@@ -1,4 +1,5 @@
 #include "ns.h"
+#include "inc/lib.h"
 
 extern union Nsipc nsipcbuf;
 
@@ -10,4 +11,20 @@ output(envid_t ns_envid)
        // LAB 6: Your code here:
        //      - read a packet from the network server
        //      - send the packet to the device driver
+       uint32_t whom;
+       int perm;
+       int32_t req;
+
+       while (1) {
+               req = ipc_recv((envid_t *)&whom, &nsipcbuf, &perm);
+               if (req != NSREQ_OUTPUT) {
+                       cprintf("not a nsreq output\n");
+                       continue;
+               }
+
+               struct jif_pkt *pkt = &(nsipcbuf.pkt);
+               while (sys_pkt_send(pkt->jp_data, pkt->jp_len) < 0) {
+                       sys_yield();
+               }
+       }
 }
```

运行`make E1000_DEBUG=TXERR,TX NET_CFLAGS=-DTESTOUTPUT_COUNT=100 run-net_testoutput`，测试结果，而`make grade`也应该通过testoutput测试。

```
// 测试结果
e1000: index 0: 0x302040 : 9000009 0
superblock is good
bitmap is good
Transmitting packet 2
e1000: index 1: 0x30262e : 9000009 0
Transmitting packet 3
e1000: index 2: 0x302c1c : 9000009 0
Transmitting packet 4
e1000: index 3: 0x30320a : 9000009 0
Transmitting packet 5
e1000: index 4: 0x3037f8 : 9000009 0
Transmitting packet 6
e1000: index 5: 0x303de6 : 9000009 0
Transmitting packet 7
e1000: index 6: 0x3043d4 : 9000009 0
Transmitting packet 8
e1000: index 7: 0x3049c2 : 9000009 0
Transmitting packet 9
e1000: index 8: 0x304fb0 : 9000009 0
e1000: index 9: 0x30559e : 9000009 0
```

# Exercize 9
阅读文档，略。

# Exercize 10
完成接收描述符队列初始化。接收描述符队列大小设置为128，RDH设置为0，而RDT设置为127。注意网卡MAC地址寄存器RAL(0x12005452)和RAH(0x5634 | E1000_RAH_AV)的值的设置。

```
diff --git a/kern/e1000.c b/kern/e1000.c
index db2941b..65d033b 100644
--- a/kern/e1000.c
+++ b/kern/e1000.c
@@ -11,6 +11,12 @@ struct e1000_tdt *tdt;
 struct e1000_tx_desc tx_desc_array[TXDESCS];
 char tx_buffer_array[TXDESCS][TX_PKT_SIZE];
 
+struct e1000_rdh *rdh;
+struct e1000_rdt *rdt;
+struct e1000_rx_desc rx_desc_array[RXDESCS];
+char rx_buffer_array[RXDESCS][RX_PKT_SIZE];
+
+uint32_t E1000_MAC[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
 int
 e1000_attachfn(struct pci_func *pcif)
 {
@@ -23,6 +29,7 @@ e1000_attachfn(struct pci_func *pcif)
        assert(*status_reg == 0x80080783);
 
        e1000_transmit_init();
+       e1000_receive_init();
 
        /*
         * transmit test
@@ -85,3 +92,52 @@ e1000_transmit(void *data, size_t len)
        tdt->tdt = next;
        return 0;
 }
+
+static void
+get_ra_address(uint32_t mac[], uint32_t *ral, uint32_t *rah)
+{
+       uint32_t low = 0, high = 0;
+       int i;
+
+       for (i = 0; i < 4; i++) {
+               low |= mac[i] << (8 * i);
+       }
+
+       for (i = 4; i < 6; i++) {
+               high |= mac[i] << (8 * i);
+       }
+
+       *ral = low;
+       *rah = high | E1000_RAH_AV;
+}
+
+static void
+e1000_receive_init()
+{
+       uint32_t *rdbal = (uint32_t *)E1000REG(E1000_RDBAL);
+       uint32_t *rdbah = (uint32_t *)E1000REG(E1000_RDBAH);
+       *rdbal = PADDR(rx_desc_array);
+       *rdbah = 0;
+
+       int i;
+       for (i = 0; i < RXDESCS; i++) {
+               rx_desc_array[i].addr = PADDR(rx_buffer_array[i]);
+       }
+
+       struct e1000_rdlen *rdlen = (struct e1000_rdlen *)E1000REG(E1000_RDLEN);
+       rdlen->len = RXDESCS;
+
+       rdh = (struct e1000_rdh *)E1000REG(E1000_RDH);
+       rdt = (struct e1000_rdt *)E1000REG(E1000_RDT);
+       rdh->rdh = 0;
+       rdt->rdt = RXDESCS-1;
+
+       uint32_t *rctl = (uint32_t *)E1000REG(E1000_RCTL);
+       *rctl = E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SECRC;
+
+       uint32_t *ra = (uint32_t *)E1000REG(E1000_RA);
+       uint32_t ral, rah;
+       get_ra_address(E1000_MAC, &ral, &rah);
+       ra[0] = ral;
+       ra[1] = rah;
+}
diff --git a/kern/e1000.h b/kern/e1000.h
index 02767c3..8d083cc 100644
--- a/kern/e1000.h
+++ b/kern/e1000.h
@@ -21,6 +21,23 @@
 #define E1000_TXD_CMD_EOP    0x00000001 /* End of Packet */
 #define E1000_TXD_CMD_RS     0x00000008 /* Report Status */
 
+
+#define RXDESCS 128
+#define RX_PKT_SIZE 1518
+#define E1000_RCTL 0x00100
+#define E1000_RCTL_EN     0x00000002    /* enable */
+#define E1000_RCTL_BAM    0x00008000    /* broadcast enable */
+#define E1000_RCTL_SECRC  0x04000000    /* Strip Ethernet CRC */
+#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
+#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
+#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
+#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
+#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */
+#define E1000_RA       0x05400  /* Receive Address - RW Array */
+#define E1000_RAH_AV   0x80000000        /* Receive descriptor valid */
+#define E1000_RXD_STAT_DD       0x01    /* Descriptor Done */
+#define E1000_RXD_STAT_EOP      0x02    /* End of Packet */
+
 enum {
        E_TRANSMIT_RETRY = 1,
 };
@@ -76,8 +93,37 @@ struct e1000_tdh {
 };
 
 
+/*receive descriptor related*/
+struct e1000_rx_desc {
+       uint64_t addr;
+       uint16_t length;
+       uint16_t chksum;
+       uint8_t status;
+       uint8_t errors;
+       uint16_t special;
+}__attribute__((packed));
+
+struct e1000_rdlen {
+       unsigned zero: 7;
+       unsigned len: 13;
+       unsigned rsv: 12;
+};
+
+struct e1000_rdh {
+       uint16_t rdh;
+       uint16_t rsv;
+};
+
+struct e1000_rdt {
+       uint16_t rdt;
+       uint16_t rsv;
+};
+
+
 int e1000_attachfn(struct pci_func *pcif);
 static void e1000_transmit_init();
 int e1000_transmit(void *data, size_t len);
 
+static void e1000_receive_init();
+
 #endif // JOS_KERN_E1000_H
```

# Exercize 11
完成接收数据包函数和添加对应系统调用。

```
diff --git a/inc/lib.h b/inc/lib.h
index 0f705b0..08a29a8 100644
--- a/inc/lib.h
+++ b/inc/lib.h
@@ -61,6 +61,7 @@ int   sys_ipc_try_send(envid_t to_env, uint32_t value, void *pg, int perm);
 int    sys_ipc_recv(void *rcv_pg);
 unsigned int sys_time_msec(void);
 int sys_pkt_send(void *data, size_t len);
+int sys_pkt_receive(void *addr, size_t *len);
 
 // This must be inlined.  Exercise for reader: why?
 static inline envid_t __attribute__((always_inline))
diff --git a/inc/syscall.h b/inc/syscall.h
index b2317cf..9134010 100644
--- a/inc/syscall.h
+++ b/inc/syscall.h
@@ -19,6 +19,7 @@ enum {
        SYS_ipc_recv,
        SYS_time_msec,
        SYS_pkt_send,
+       SYS_pkt_recv,
        NSYSCALLS
 };
 
diff --git a/kern/e1000.c b/kern/e1000.c
index 65d033b..d36c852 100644
--- a/kern/e1000.c
+++ b/kern/e1000.c
@@ -141,3 +141,22 @@ e1000_receive_init()
        ra[0] = ral;
        ra[1] = rah;
 }
+
+int
+e1000_receive(void *addr, size_t *len)
+{
+       static int32_t next = 0;
+       if(!(rx_desc_array[next].status & E1000_RXD_STAT_DD)) {
+               return -E_RECEIVE_RETRY;
+       }
+       if(rx_desc_array[next].errors) {
+               cprintf("receive errors\n");
+               return -E_RECEIVE_RETRY;
+       }
+       *len = rx_desc_array[next].length;
+       memcpy(addr, rx_buffer_array[next], *len);
+
+       rdt->rdt = (rdt->rdt + 1) % RXDESCS;
+       next = (next + 1) % RXDESCS;
+       return 0;
+}
diff --git a/kern/e1000.h b/kern/e1000.h
index 8d083cc..885d141 100644
--- a/kern/e1000.h
+++ b/kern/e1000.h
@@ -40,6 +40,7 @@
 
 enum {
        E_TRANSMIT_RETRY = 1,
+       E_RECEIVE_RETRY,
 };
 
 
@@ -125,5 +126,6 @@ static void e1000_transmit_init();
 int e1000_transmit(void *data, size_t len);
 
 static void e1000_receive_init();
+int e1000_receive(void *addr, size_t *len);
 
 #endif // JOS_KERN_E1000_H
diff --git a/kern/syscall.c b/kern/syscall.c
index 547fe79..0f9adfe 100644
--- a/kern/syscall.c
+++ b/kern/syscall.c
@@ -398,13 +398,18 @@ sys_time_msec(void)
        return time_msec();
 }
 
-
 static int
 sys_pkt_send(void *data, int len)
 {
        return e1000_transmit(data, len);
 }
 
+static int
+sys_pkt_recv(void *addr, size_t *len)
+{
+       return e1000_receive(addr, len);
+}
+
 // Dispatches to the correct kernel function, passing the arguments.
 int32_t
 syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
@@ -450,6 +455,8 @@ syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4,
                return sys_time_msec();
        case SYS_pkt_send:
                return sys_pkt_send((void *)a1, a2);
+       case SYS_pkt_recv:
+               return sys_pkt_recv((void *)a1, (size_t *)a2);
        default:
                return -E_INVAL;
        }
diff --git a/lib/syscall.c b/lib/syscall.c
index bd3a31b..da33b5d 100644
--- a/lib/syscall.c
+++ b/lib/syscall.c
@@ -128,3 +128,9 @@ sys_pkt_send(void *data, size_t len)
 {
        return syscall(SYS_pkt_send, 1, (uint32_t)data, len, 0, 0, 0);
 }
+
+int
+sys_pkt_recv(void *addr, size_t *len)
+{
+       return syscall(SYS_pkt_recv, 1, (uint32_t)addr, (uint32_t)len, 0, 0, 0);
+}
```

# Exercize 12
完成`net/input.c`，实现从网卡读取数据包并发送给core network server进程。

```
diff --git a/net/input.c b/net/input.c
index 4e08f0f..812dc6b 100644
--- a/net/input.c
+++ b/net/input.c
@@ -1,8 +1,23 @@
 #include "ns.h"
+#include "inc/lib.h"
+#include "kern/e1000.h"
 
 extern union Nsipc nsipcbuf;
 
 void
+sleep(int msec)
+{
+       unsigned now = sys_time_msec();
+       unsigned end = now + msec;
+
+       if ((int)now < 0 && (int)now > -MAXERROR)
+               panic("sys_time_msec: %e", (int)now);
+
+       while (sys_time_msec() < end)
+               sys_yield();
+}
+
+void
 input(envid_t ns_envid)
 {
        binaryname = "ns_input";
@@ -13,4 +28,15 @@ input(envid_t ns_envid)
        // Hint: When you IPC a page to the network server, it will be
        // reading from it for a while, so don't immediately receive
        // another packet in to the same physical page.
+       size_t len;
+       char buf[RX_PKT_SIZE];
+       while (1) {
+               if (sys_pkt_recv(buf, &len) < 0) {
+                       continue;
+               }
+               memcpy(nsipcbuf.pkt.jp_data, buf, len);
+               nsipcbuf.pkt.jp_len = len;
+               ipc_send(ns_envid, NSREQ_INPUT, &nsipcbuf, PTE_P|PTE_U|PTE_W);
+               sleep(50);
+       }
 }
```
完成后运行测试程序`make E1000_DEBUG=TX,TXERR,RX,RXERR,RXFILTER run-net_testinput`，可以看到类似如下输出，同时`make grade`可以通过`echosrv`测试。

```
e1000: index 0: 0x307040 : 900002a 0
e1000: unicast match[0]: 52:54:00:12:34:56
input: 0000   5254 0012 3456 5255  0a00 0202 0806 0001
input: 0010   0800 0604 0002 5255  0a00 0202 0a00 0202
input: 0020   5254 0012 3456 0a00  020f 0000 0000 0000
input: 0030   0000 0000 0000 0000  0000 0000 0000 0000
```

# Exercize 13
完成`user/httpd.c`的`send_data()`和`send_file()`两个函数。

```
diff --git a/user/httpd.c b/user/httpd.c
index ede43bf..e74a4c3 100644
--- a/user/httpd.c
+++ b/user/httpd.c
@@ -77,7 +77,18 @@ static int
 send_data(struct http_request *req, int fd)
 {
        // LAB 6: Your code here.
-       panic("send_data not implemented");
+       // panic("send_data not implemented");
+       struct Stat stat;
+       fstat(fd, &stat);
+       void *buf = malloc(stat.st_size);
+       if (readn(fd, buf, stat.st_size) != stat.st_size)
+               panic("Failed to read requested file");
+
+       if (write(req->sock, buf, stat.st_size) != stat.st_size)
+               panic("Failed to send bytes to client");
+
+       free(buf);
+       return 0;
 }
 
 static int
@@ -223,7 +234,20 @@ send_file(struct http_request *req)
        // set file_size to the size of the file
 
        // LAB 6: Your code here.
-       panic("send_file not implemented");
+       // panic("send_file not implemented");
+       if ((fd = open(req->url, O_RDONLY)) < 0) {
+               send_error(req, 404);
+               goto end;
+       }
+
+       struct Stat stat;
+       fstat(fd, &stat);
+       if (stat.st_isdir) {
+               send_error(req, 404);
+               goto end;
+       }
+
+       file_size = stat.st_size;
 
        if ((r = send_header(req, 200)) < 0)
                goto end;
```
