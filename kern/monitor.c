// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display backtrace information", mon_backtrace },
	{ "showmappings", "Display mapping information", mon_showmappings },
	{ "setperm", "Set mapping page perm", mon_setperm },
};

/***** Implementations of basic kernel monitor commands *****/


void
pte_print(pte_t *pte)
{
	char perm_w = (*pte & PTE_W) ? 'W' : '-';
	char perm_u = (*pte & PTE_U) ? 'U' : '-';
	cprintf("perm: P%c%c\n", perm_w, perm_u);
}

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

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
			cprintf(" %08x ", args[i]);
		}
		cprintf("\n");

		struct Eipdebuginfo debug_info;
		debuginfo_eip(eip, &debug_info);
		cprintf("\t%s:%d: %.*s+%d\n",
			debug_info.eip_file, debug_info.eip_line, debug_info.eip_fn_namelen,
			debug_info.eip_fn_name, eip - debug_info.eip_fn_addr);

		ebp = (uint32_t *) *ebp;
	}
	return 0;
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


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
