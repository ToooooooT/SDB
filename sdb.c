#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <capstone/capstone.h>

#define errquit(m) { perror(m); exit(-1); }
#define RAX_OFFSET (10 * 8)
#define RIP_OFFSET (16 * 8)
#define MAXTABLESIZE 256
#define MAXSNAPSHOTENTRY 256
#define hash(x) ((x) & (MAXTABLESIZE - 1))
#define isExit(x) { if (WIFEXITED(status)) {                                    \
                        printf("** the target program terminated\n");           \
                        exit(0);                                                \
                    }}  

typedef struct {
    unsigned long address;
    uint8_t origin_byte;
} breakpoint_t;

typedef struct node {
    breakpoint_t b;
    struct node *next;
} bNode_t;

typedef struct {
    unsigned long long start, end;
    unsigned long *buffer;
} snapshot_t;

void show_inst (char *elf, Elf64_Shdr *text_shdr, pid_t child, csh handle, bool isTimetravel);
void recover_inst (unsigned long rip, pid_t child, bNode_t *break_table[]);
void handle_si (pid_t child, bNode_t *break_table[]);
int handle_break (Elf64_Shdr *text_shdr, Elf64_Addr entry_point, pid_t child, bNode_t *break_table[], long break_table_index[], unsigned long *max_breakpoint_idx, char command[]);
int handle_delete (pid_t child, bNode_t *break_table[], long break_table_index[], unsigned long max_breakpoint_idx, char command[]);
void handle_cont (pid_t child, bNode_t *break_table[]);
int handle_info(pid_t child, bNode_t *break_table[], long break_table_index[], unsigned long max_breakpoint_idx, char command[]);
void handle_anchor (pid_t child, snapshot_t snapshots[], struct user_regs_struct **saveGPR);
int handle_timetravel (pid_t child, bNode_t *break_table[], long break_table_index[], unsigned long max_breakpoint_idx, snapshot_t snapshots[], struct user_regs_struct *saveGPR);

int main (int argc, char *argv[]) 
{
    if (argc < 2) errquit("usage: program [args ...]");
    pid_t child;
    if ((child = fork()) < 0) errquit("fork");
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) errquit("ptrace");
        execvp(argv[1], argv + 1);
        errquit("execvp");
    } else {
        int status;
        if (waitpid(child, &status, 0) < 0) errquit("wait");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        // find entry point and text section
        char *filepath = argv[1];
        int fd = open(filepath, O_RDONLY);
        struct stat st;
        stat(filepath, &st);
        int size = st.st_size;
        char *elf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        Elf64_Ehdr *ehdr = (Elf64_Ehdr*) elf;
        Elf64_Addr entry_point = ehdr->e_entry; // entry point of the child process
        Elf64_Shdr *shdr = (Elf64_Shdr *)(elf + ehdr->e_shoff); // section header table address
        int shnum = ehdr->e_shnum;  // section header entries
        Elf64_Shdr *sh_strtab = shdr + ehdr->e_shstrndx; // string table section which is in section header table
        const char *const sh_strtab_p = elf + sh_strtab->sh_offset; // sh_offset is the byte offset of the file to this section
        Elf64_Shdr *text_shdr;
        for (int i = 0; i < shnum; ++i) {
            if (!strcmp(sh_strtab_p + shdr[i].sh_name, ".text"))
                text_shdr = shdr + i;
        }

        // initialize capstone
        csh handle;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errquit("Failed to initialize capstone");

        // start program
        printf("** program '%s' loaded. entry point 0x%lx\n", filepath, entry_point);
        show_inst(elf, text_shdr, child, handle, false);

        // initialize breakpoint table
        bNode_t *break_table[MAXTABLESIZE];
        memset(break_table, 0, sizeof(bNode_t *) * MAXTABLESIZE);
        long break_table_index[MAXTABLESIZE << 2]; // store breakpoint address in index order
        memset(break_table_index, 0xffffffff, sizeof(long) * (MAXTABLESIZE << 2));
        unsigned long max_breakpoint_idx = 0;

        // initialize snapshot table store memory
        snapshot_t snapshots[MAXSNAPSHOTENTRY];
        memset(snapshots, 0, sizeof(snapshot_t) * MAXSNAPSHOTENTRY);
        // 
        struct user_regs_struct *saveGPR = NULL;


        // start debugging
        while (true) {
            printf("(sdb)  ");
            char command[100] = {0};
            fgets(command, sizeof(command), stdin);
            command[strlen(command) - 1] = 0; // modify '\n' to '\0'
            if (!strcmp(command, "si")) {
                handle_si(child, break_table);
                show_inst(elf, text_shdr, child, handle, false);
            } else if (!strncmp(command, "b 0x", 4) || !strncmp(command, "break 0x", 8)) {
                if (handle_break(text_shdr, entry_point, child, break_table, break_table_index, &max_breakpoint_idx, command) == -1)
                    printf("** invalid command!\n");
            } else if (!strncmp(command, "d ", 2) || !strncmp(command, "delete ", 7)) {
                if (handle_delete(child, break_table, break_table_index, max_breakpoint_idx, command) == -1)
                    printf("** invalid command!\n");
            } else if (!strcmp(command, "c") || !strcmp(command, "cont")) {
                handle_cont(child, break_table);
                show_inst(elf, text_shdr, child, handle, false);
            } else if (!strncmp(command, "info ", 5)) {
                if (handle_info(child, break_table, break_table_index, max_breakpoint_idx, command) == -1)
                    printf("** invalid command!\n");
            } else if (!strcmp(command, "anchor")) {
                handle_anchor (child, snapshots, &saveGPR);
                printf("** dropped an anchor\n");
            } else if (!strcmp(command, "timetravel")) {
                if (handle_timetravel(child, break_table, break_table_index, max_breakpoint_idx, snapshots, saveGPR) == 0) {
                    printf("** go back to the anchor point\n");
                    show_inst(elf, text_shdr, child, handle, true);
                }
            } else if (!strcmp(command, "q") || !strcmp(command, "quit")) {
                printf("quit!\n");
                return 0;
            } else if (strlen(command))
                printf("** invalid command!\n");

            if (waitpid(child, &status, WNOHANG) < 0) errquit("wait");
            isExit(status);
        }

        cs_close(&handle);
    }
}

void show_inst (char *elf, Elf64_Shdr *text_shdr, pid_t child, csh handle, bool isTimetravel) 
{
    unsigned long rip = ptrace(PTRACE_PEEKUSER, child, RIP_OFFSET, 0);
    if ((ptrace(PTRACE_PEEKTEXT, child, rip, 0) & 0xff) == 0xcc && !isTimetravel) {
        // current instruction is breakpoint
        printf("** hit a breakpoint at %p\n", (void *)rip);
    }
    char *text = elf + text_shdr->sh_offset;
    cs_insn *insn;
    size_t count = cs_disasm(handle, (uint8_t *) text + rip - text_shdr->sh_addr, text_shdr->sh_size - (rip - text_shdr->sh_addr), rip, 5, &insn);
    for (size_t i = 0; i < count; ++i) {
        printf("\t0x%"PRIx64": ", insn[i].address);
        for (int j = 0; j < insn[i].size; ++j)
            printf("%02x ", insn[i].bytes[j]);
        for (int j = 0; j < 7 - insn[i].size; ++j) // print for alignment
            printf("   ");
        printf("\t\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
    }
    if (count < 5)
        printf("** the address is out of the range of the text section.\n");

    cs_free(insn, count);
}

void recover_inst (unsigned long rip, pid_t child, bNode_t *break_table[]) 
{
    int idx = hash(rip);
    for (bNode_t **p = break_table + idx; *p; p = &((*p)->next)) {
        if ((*p)->b.address == rip) {
            unsigned long inst = ptrace(PTRACE_PEEKTEXT, child, rip, 0);
            *(uint8_t *)&inst = (*p)->b.origin_byte;
            ptrace(PTRACE_POKETEXT, child, rip, inst);
            break;
        }
    }
}

void handle_si (pid_t child, bNode_t *break_table[]) 
{
    // // first add 0xcc on next instruction, then continue and recover the original next instruction
    int status;
    unsigned long rip = (unsigned long) ptrace(PTRACE_PEEKUSER, child, RIP_OFFSET, 0);
    bool isBreak = false;

    if ((ptrace(PTRACE_PEEKTEXT, child, rip, 0) & 0xff) == 0xcc) {
        // current instruction is breakpoint
        isBreak = true;
        recover_inst(rip, child, break_table);
    }

    ptrace(PTRACE_SINGLESTEP, child, 0, 0);
    if (waitpid(child, &status, 0) < 0) errquit("wait");
    isExit(status);

    if (isBreak) {
        // reset the breakpoint
        unsigned long inst = ptrace(PTRACE_PEEKTEXT, child, rip, 0);
        *(uint8_t *)&inst = 0xcc;
        ptrace(PTRACE_POKETEXT, child, rip, inst);
    }
}

int handle_break (Elf64_Shdr *text_shdr, Elf64_Addr entry_point, pid_t child, bNode_t *break_table[], long break_table_index[], unsigned long *max_breakpoint_idx, char command[]) 
{
    unsigned long address;
    sscanf(command, "%*s %lx", &address);
    if (address < text_shdr->sh_addr || address > text_shdr->sh_addr + text_shdr->sh_size) {
        printf("** invalid address: %p, address should be in range (%p ~ %p)\n", (void *)address, (void *)entry_point, (void *)(entry_point + text_shdr->sh_size));
        return -1;
    }
    break_table_index[*max_breakpoint_idx] = address;
    *max_breakpoint_idx += 1;
    unsigned long inst = ptrace(PTRACE_PEEKTEXT, child, address, 0);
    bNode_t *new = malloc(sizeof(bNode_t));
    new->b.address = address;
    new->b.origin_byte = *(uint8_t *)&inst;
    int idx = hash(new->b.address);
    new->next = break_table[idx];
    break_table[idx] = new;
    *(uint8_t *)&inst = 0xcc;
    ptrace(PTRACE_POKETEXT, child, address, inst);
    printf("** set a breakpoint at %p\n", (void *)address);
    return 0;
}

int handle_delete (pid_t child, bNode_t *break_table[], long break_table_index[], unsigned long max_breakpoint_idx, char command[]) 
{
    unsigned long id;
    char info[20] = {0};
    sscanf(command, "%*s %s %ld", info, &id);
    if (strcmp(info, "b") && strcmp(info, "break") && strcmp(info, "breakpoint"))
        return -1;
    else if (id > max_breakpoint_idx || break_table_index[id - 1] == -1) {
        printf("** breakpoint %ld does not exist.\n", id);
        return -2;
    } else {
        unsigned long address = break_table_index[id - 1];
        int idx = hash(address);
        for (bNode_t **p = break_table + idx; *p; p = &((*p)->next)) {
            if ((*p)->b.address == address) {
                bNode_t *tmp = *p;
                *p = (*p)->next;
                // delete 0xcc
                unsigned long inst = ptrace(PTRACE_PEEKTEXT, child, tmp->b.address, 0);
                *(uint8_t *)&inst = tmp->b.origin_byte;
                ptrace(PTRACE_POKETEXT, child, address, inst);
                free(tmp);
                break;
            }
        }
        break_table_index[id - 1] = -1;
        printf("** delete breakpoint %ld.\n", id);
    }
    return 0;
}

void handle_cont (pid_t child, bNode_t *break_table[]) 
{
    handle_si(child, break_table);
    int status;
    ptrace(PTRACE_CONT, child, 0, 0);
    if (waitpid(child, &status, 0) < 0) errquit("wait");
    isExit(status);
    // back 1 rip
    unsigned long rip = ptrace(PTRACE_PEEKUSER, child, RIP_OFFSET, 0);
    rip -= 1;
    ptrace(PTRACE_POKEUSER, child, RIP_OFFSET, rip);
}

int handle_info(pid_t child, bNode_t *break_table[], long break_table_index[], unsigned long max_breakpoint_idx, char command[]) {
    char info[100] = {0};
    sscanf(command, "%*s %s", info);
    if (strcmp(info, "b") && strcmp(info, "break") && strcmp(info, "breakpoint"))
        return -1;
    
    for (unsigned long i = 0; i < max_breakpoint_idx; ++i) {
        if (break_table_index[i] != -1) {
            int idx = hash(break_table_index[i]);
            for (bNode_t *p = break_table[idx]; p; p = p->next) {
                if (p->b.address == break_table_index[i]) {
                    printf("breakpoint %ld : %p\n", i + 1, (void *)(p->b.address));
                    break;
                }
            }
        }
    }
    return 0;
}

void handle_anchor (pid_t child, snapshot_t snapshots[], struct user_regs_struct **saveGPR) {
    // clear old snapshots
    for (int i = 0; i < MAXSNAPSHOTENTRY; ++i) {
        if (snapshots[i].start > 0)
            free(snapshots[i].buffer);
        else
            break;
    }
    memset(snapshots, 0, sizeof(snapshot_t) * MAXSNAPSHOTENTRY);

    int fd, sz;
	char buf[65536], *s = buf, *line, *saveptr, permission[5] = {0};
    unsigned long long start, end;
    char f[50] = {0};
    sprintf(f, "/proc/%d/maps", child);
	if((fd = open(f, O_RDONLY)) < 0) errquit("get_base_and_fname/open");
    while((sz = read(fd, s, sizeof(buf)-1-(s-buf))) > 0) { s += sz; }
    *s = 0;
    s = buf;
	close(fd);
    int cnt = 0; // count for how many zone to be snapshot
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { 
        s = NULL;
		if(sscanf(line, "%llx-%llx %s %*s %*s %*s %*s", &start, &end, permission) != 3) errquit("get_base_and_fname");
        if (permission[1] == 'w') {
            // if this zone can write then snapshot it
            snapshots[cnt].start = start;
            snapshots[cnt].end = end;
            // snapshot the process memory
            snapshots[cnt].buffer = malloc(end - start);
            unsigned long *p = snapshots[cnt].buffer;
            for (unsigned long i = start; i < end; i += 8) {
                *p = (unsigned long) ptrace(PTRACE_PEEKTEXT, child, i, 0);
                p++;
            }
            cnt++;
        }
	}
    // save general purpose registers
    if (!*saveGPR)
        *saveGPR = malloc(sizeof(struct user_regs_struct));
    ptrace(PTRACE_GETREGS, child, 0, *saveGPR);
}

int handle_timetravel (pid_t child, bNode_t *break_table[], long break_table_index[], unsigned long max_breakpoint_idx, snapshot_t snapshots[], struct user_regs_struct *saveGPR) {
    if (!saveGPR) {
        printf("** No anchor point is dropped!\n");
        return -1;
    }
    // recover general purpose registers
    ptrace(PTRACE_SETREGS, child, 0, saveGPR);
    // recover process memory
    for (int i = 0; i < MAXSNAPSHOTENTRY; ++i) {
        if (snapshots[i].start == 0)
            break;
        unsigned long *p = snapshots[i].buffer;
        for (unsigned long long j = snapshots[i].start, start = snapshots[i].start, end = snapshots[i].end; j < end; j += 8)
            ptrace(PTRACE_POKETEXT, child, j, p[(j - start) >> 3]);
    }
    // reset all breakpoint
    for (int i = 0; i < max_breakpoint_idx; ++i) {
        if (break_table_index[i] > 0) {
            // set 0xcc
            unsigned long inst = ptrace(PTRACE_PEEKTEXT, child, break_table_index[i], 0);
            *(uint8_t *)&inst = 0xcc;
        }
    }
    return 0;
}