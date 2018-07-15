#include <kern/e1000.h>
#include <kern/pmap.h>

// LAB 6: Your driver code here
int
e1000_attachfn(struct pci_func *pcif)
{
	pci_func_enable(pcif);
	cprintf("reg_base:%x, reg_size:%x\n", pcif->reg_base[0], pcif->reg_size[0]);
	return 0;
}
