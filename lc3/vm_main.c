#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/termios.h>

#include "vm.h"
#include "compiler.h"

#define MEMORY_MAX (1 << 16)
#define lc_ntoh16(x) vm_ntohs(x)

static uint16_t memory[MEMORY_MAX];  /* 65536 locations */
static uint16_t reg[R_COUNT];

static struct termios original_tio;

void disable_input_buffering()
{
    tcgetattr(STDIN_FILENO, &original_tio);
    struct termios new_tio = original_tio;
    new_tio.c_lflag &= ~ICANON & ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
}

void restore_input_buffering()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &original_tio);
}

uint16_t check_key()
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    return select(1, &readfds, NULL, NULL, &timeout) != 0;
}

void handle_interrupt(int signal)
{
    restore_input_buffering();
    printf("\n");
    exit(-2);
}

uint16_t sign_extend(uint16_t x, int bit_count)
{
    if ((x >> (bit_count - 1)) & 1) {
        x |= (0xFFFF << bit_count);
    }
    return x;
}

void update_flags(uint16_t r)
{
    if (reg[r] == 0) {
        reg[R_COND] = FL_ZRO;
    } else if (reg[r] >> 15) {
        /* a 1 in the left-most bit indicates negative */ 
        reg[R_COND] = FL_NEG;
    } else {
        reg[R_COND] = FL_POS;
    }
}

void read_image_file(int fd)
{
    /* the origin tells us where in memory to place the image */
    uint16_t origin;
    read(fd, &origin, sizeof(origin));
    origin = lc_ntoh16(origin);

    /* we know the maximum file size so we only need one fread */
    uint16_t max_read = MEMORY_MAX - origin;
    uint16_t* p = memory + origin;
    size_t read_ret = read(fd, p, sizeof(uint16_t) * max_read);

    /* swap to little endian */
    while (read_ret-- > 0) {
        *p = lc_ntoh16(*p);
        ++p;
    }
}

int read_image(const char* image_path)
{
    int fd = open(image_path, O_RDONLY);
    if (fd < 0) { return 0; };
    read_image_file(fd);
    close(fd);
    return 1;
}

void mem_write(uint16_t address, uint16_t val)
{
    memory[address] = val;
}

uint16_t mem_read(uint16_t address)
{
    if (address == MR_KBSR) {
        if (check_key()) {
            memory[MR_KBSR] = (1 << 15);
            memory[MR_KBDR] = getchar();
        } else {
            memory[MR_KBSR] = 0;
        }
    }
    return memory[address];
}

int instruction_add(uint16_t instr)
{
    /* Instruction format:
        Register mode (Mode bit 0):
        15          Dest    Src1   Mode       Src2  0
        |-------------------------------------------|
        | 0 0 0 1 | D D D | A A A | 0 | 0 0 | B B B |
        |-------------------------------------------|
        D D D = 3-bit Destination Register
        A A A = 3-bit Source 1 Register
        B B B = 3-bit Source 2 Register
        Immediate mode (Mode bit 1):
        15          Dest    Src1  Mode  Immediate   0
        |-------------------------------------------|
        | 0 0 0 1 | D D D | A A A | 1 | I I I I I   |
        |-------------------------------------------|
        D D D = 3-bit Destination Register
        A A A = 3-bit Source 1 Register
        I I I I I = 5-bit Immediate Value Two's Complement Integer
        NOTE: The immediate value must be sign extended
    */

    uint16_t r0 = R0(instr);
    /* first operand (SR1) */
    uint16_t r1 = R1(instr);
    /* whether we are in immediate mode */
    uint16_t imm_flag = IMM(instr);

    if (imm_flag) {
        uint16_t imm5 = sign_extend(instr & 0x1F, 5);
        reg[r0] = reg[r1] + imm5;
    } else {
        uint16_t r2 = instr & 0x7;
        reg[r0] = reg[r1] + reg[r2];
    }
    update_flags(r0);
    return 0;
}

int instruction_and(uint16_t instr)
{
    /* Instruction format:
        Register mode (Mode bit 0):
        15          Dest    Src1   Mode       Src2  0
        |-------------------------------------------|
        | 0 1 0 1 | D D D | A A A | 0 | 0 0 | B B B |
        |-------------------------------------------|
        D D D = 3-bit Destination Register
        A A A = 3-bit Source 1 Register
        B B B = 3-bit Source 2 Register
        Immediate mode (Mode bit 1):
        15          Dest    Src1  Mode  Immediate   0
        |-------------------------------------------|
        | 0 1 0 1 | D D D | A A A | 1 | I I I I I   |
        |-------------------------------------------|
        D D D = 3-bit Destination Register
        A A A = 3-bit Source 1 Register
        I I I I I = 5-bit Immediate Value Two's Complement Integer
        NOTE: The immediate value must be sign extended
    */
    uint16_t r0 = R0(instr);
    uint16_t r1 = R1(instr);
    uint16_t imm_flag = IMM(instr);

    if (imm_flag) {
        uint16_t imm5 = sign_extend(instr & 0x1F, 5);
        reg[r0] = reg[r1] & imm5;
    } else {
        uint16_t r2 = instr & 0x7;
        reg[r0] = reg[r1] & reg[r2];
    }
    update_flags(r0);
    return 0;
}

int instruction_not(uint16_t instr)
{
    /* Instruction Format:
        15          Dest    Src    Mode             0
        |-------------------------------------------|
        | 1 0 0 1 | D D D | S S S | 1 | 1 1 1 1 1   |
        |-------------------------------------------|
        D D D = 3-bit Destination Register
        S S A = 3-bit Source Register
    */
    uint16_t r0 = R0(instr);
    uint16_t r1 = R1(instr);

    reg[r0] = ~reg[r1];
    update_flags(r0);
    return 0;
}

int instruction_branch(uint16_t instr)
{
    /* Instruction Format:
    15          Flags   PCOffset9               0
    |-------------------------------------------|
    | 0 0 0 0 | N Z P | P P P P P P P P P       |
    |-------------------------------------------|
    N = Negative Flag (BRN)
    Z = Zero Flag (BRZ)
    P = Positive Flag (BRP)
    P P P P P P P P P = PCOffset9
    Flags can be combined to produce additional branch opcodes:
    BRZP
    BRNP
    BRNZ
    BRNZP (also equal to BR)
    Sign extend PCOffset9 and add to PC.
    */
    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
    uint16_t cond_flag = (instr >> 9) & 0x7;
    if (cond_flag & reg[R_COND]) {
        reg[R_PC] += pc_offset;
    }
    return 0;
}

int instruction_jmp(uint16_t instr)
{
    /* Instruction Format:
    JMP mode:
        15                 Register                 0
        |-------------------------------------------|
        | 1 1 0 0 | 0 0 0 | R R R | 0 0 0 0 0 0     |
        |-------------------------------------------|
        R R R = 3-bit base register
    RET mode:
        15                                          0
        |-------------------------------------------|
        | 1 1 0 0 | 0 0 0 | 1 1 1 | 0 0 0 0 0 0     |
        |-------------------------------------------|
        
        NOTE: RET always loads R7
    */
    /* Also handles RET */
    uint16_t r1 = R1(instr);
    reg[R_PC] = reg[r1];
    return 0;
}

int instruction_jsr(uint16_t instr)
{
    /* Instruction Format:
    JSR mode:
        15             PCOffset11                   0
        |-------------------------------------------|
        | 0 1 0 0 | 1 | P P P | P P P | P P P | P P |
        |-------------------------------------------|
        P P P P P P P P P P P = PCOffset11
    JSRR mode:
        15                   Register               0
        |-------------------------------------------|
        | 0 1 0 0 | 0 | 0 0 | R R R | 0 0 0 0 0 0   |
        |-------------------------------------------|
        R R R = 3-bit base register
    */
    uint16_t long_flag = (instr >> 11) & 1;
    reg[R_R7] = reg[R_PC];
    if (long_flag) {
        uint16_t long_pc_offset = sign_extend(instr & 0x7FF, 11);
        reg[R_PC] += long_pc_offset;  /* JSR */
    } else {
        uint16_t r1 = R1(instr);
        reg[R_PC] = reg[r1]; /* JSRR */
    }
    return 0;
}

int instruction_ld(uint16_t instr)
{
    /* Instruction Format:
    15          Dest   PCOffset9                0
    |-------------------------------------------|
    | 0 0 1 0 | D D D | P P P P P P P P P       |
    |-------------------------------------------|
    D D D = 3-bit Destination Register
    P P P P P P P P P = PCOffset9
    Sign extend PCOffset9 and add to PC.
    Load the value at that memory address into destination
    */
    uint16_t r0 = R0(instr);
    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
    reg[r0] = mem_read(reg[R_PC] + pc_offset);
    update_flags(r0);
    return 0;
}

int instruction_ldi(uint16_t instr)
{
    /* Instruction Format:
        15          Dest   PCOffset9                0
        |-------------------------------------------|
        | 1 0 1 0 | D D D | P P P P P P P P P       |
        |-------------------------------------------|
        D D D = 3-bit Destination Register
        P P P P P P P P P = PCOffset9
        Sign extend PCOffset9 and add to PC. The value
        stored at that memory location (A) is another address (B). 
        The value stored in memory location B is loaded
        into the destination register.
        (A points to B. The value is located at memory location B)
    */
    /* destination register (DR) */
    uint16_t r0 = R0(instr);
    /* PCoffset 9*/
    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
    /* add pc_offset to the current PC, look at that memory location to get the final address */
    reg[r0] = mem_read(mem_read(reg[R_PC] + pc_offset));
    update_flags(r0);
    return 0;
}

int instruction_ldr(uint16_t instr)
{
    /* Instruction Format:
        15          Dest   Base     Offset6         0
        |-------------------------------------------|
        | 0 1 1 0 | D D D | B B B | O O O O O O     |
        |-------------------------------------------|
        D D D = 3-bit Destination Register
        B B B = 3-bit Base Register
        O O O O O O = 6-bit offset
        Sign extend the offset, add this value to
        the value in the base register. Read the 
        memory at this location and load into
        destination
    */
    uint16_t r0 = R0(instr);
    uint16_t r1 = R1(instr);
    uint16_t offset = sign_extend(instr & 0x3F, 6);
    reg[r0] = mem_read(reg[r1] + offset);
    update_flags(r0);
    return 0;
}

int instruction_lea(uint16_t instr)
{
    /* Instruction Format:
        15          Dest   PCOffset9                0
        |-------------------------------------------|
        | 1 1 1 0 | D D D | P P P P P P P P P       |
        |-------------------------------------------|
        D D D = 3-bit Destination Register
        P P P P P P P P P = PCOffset9
        Sign extend PCOffset9, add to PC, and store
        that ADDRESS in the destination register
    */

    uint16_t r0 = R0(instr);
    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
    reg[r0] = reg[R_PC] + pc_offset;
    update_flags(r0);
    return 0;
}

int instruction_st(uint16_t instr)
{
    /* Instruction Format:
    15          Src    PCOffset9                0
    |-------------------------------------------|
    | 0 0 1 1 | S S S | P P P P P P P P P       |
    |-------------------------------------------|
    S S S = 3-bit Source Register
    P P P P P P P P P = PCOffset9
    Sign extend PCOffset9, add to PC, and read
    the value from the source register into
    that memory location
    */
    uint16_t r0 = R0(instr);
    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
    mem_write(reg[R_PC] + pc_offset, reg[r0]);
    return 0;
}

int instruction_sti(uint16_t instr)
{
    /* Instruction Format:
    15          Src    PCOffset9                0
    |-------------------------------------------|
    | 1 0 1 1 | S S S | P P P P P P P P P       |
    |-------------------------------------------|
    S S S = 3-bit Source Register
    P P P P P P P P P = PCOffset9
    Sign extend PCOffset9, add to PC to get an address. 
    Read the value from the source register and
    store in the computed address.
    */
    uint16_t r0 = R0(instr);
    uint16_t pc_offset = sign_extend(instr & 0x1FF, 9);
    mem_write(mem_read(reg[R_PC] + pc_offset), reg[r0]);
    return 0;
}

int instruction_str(uint16_t instr)
{
    /* Instruction Format:
    15          Src    Base     Offset6         0
    |-------------------------------------------|
    | 0 1 1 1 | S S S | B B B | O O O O O O     |
    |-------------------------------------------|
    S S S = 3-bit Destination Register
    B B B = 3-bit Base Register
    O O O O O O = 6-bit offset
    Sign extend the offset, add this value to
    the value in the base register. Read the 
    value in the source register and store
    into memory at the computed address
    */
    uint16_t r0 = R0(instr);
    uint16_t r1 = R1(instr);
    uint16_t offset = sign_extend(instr & 0x3F, 6);
    mem_write(reg[r1] + offset, reg[r0]);
    return 0;
}

int instruction_trap(uint16_t instr)
{
    /* Instruction Format:
    15          Src         trapvect8         
    |-------------------------------------------|
    | 1 1 1 1 | 0 0 0 0 |  O O O O O O O O     |
    |-------------------------------------------|
    O O O O O O O O = trapvect8
    program counter tp R7, 
    zero extend travect8 is starting address of a system call.
    */
    int running = 1;
    reg[R_R7] = reg[R_PC];
    switch (instr & 0xFF)
    {
        case TRAP_GETC:
            /* read a single ASCII char */
            reg[R_R0] = (uint16_t)getchar();
            update_flags(R_R0);
            break;
        case TRAP_OUT:
            putc((char)reg[R_R0], stdout);
            fflush(stdout);
            break;
        case TRAP_PUTS:
            {
                /* one char per word */
                uint16_t* c = memory + reg[R_R0];
                while (*c) {
                    putc((char)*c, stdout);
                    ++c;
                }
                fflush(stdout);
            }
            break;
        case TRAP_IN:
            {
                printf("Enter a character: ");
                char c = getchar();
                putc(c, stdout);
                fflush(stdout);
                reg[R_R0] = (uint16_t)c;
                update_flags(R_R0);
            }
            break;
        case TRAP_PUTSP:
            {
                /* one char per byte (two bytes per word)
                    here we need to swap back to
                    big endian format */
                uint16_t* c = memory + reg[R_R0];
                while (*c) {
                    char char1 = (*c) & 0xFF;
                    putc(char1, stdout);
                    char char2 = (*c) >> 8;
                    if (char2) putc(char2, stdout);
                    ++c;
                }
                fflush(stdout);
            }
            break;
        case TRAP_HALT:
            puts("HALT");
            fflush(stdout);
            running = 0;
            break;
    }
    return running;
}

typedef int (*op_runner)(uint16_t);

static op_runner op_runners[] = {
    [OP_BR] = instruction_branch,
    [OP_ADD] = instruction_add,
    [OP_LD] = instruction_ld,
    [OP_ST] = instruction_st,
    [OP_JSR] = instruction_jsr,
    [OP_AND] = instruction_and,
    [OP_LDR] = instruction_ldr,
    [OP_STR] = instruction_str,

    [OP_NOT] = instruction_not,
    [OP_LDI] = instruction_ldi,
    [OP_STI] = instruction_sti,
    [OP_JMP] = instruction_jmp,
    [OP_LEA] = instruction_lea,
    [OP_TRAP] = instruction_trap,
};

int main(int argc, const char* argv[])
{
    if (argc < 2) {
        /* show usage string */
        printf("lc3 [image-file1] ...\n");
        exit(2);
    }

    for (int j = 1; j < argc; ++j) {
        if (!read_image(argv[j])) {
            printf("failed to load image: %s\n", argv[j]);
            exit(1);
        }
    }

    signal(SIGINT, handle_interrupt);
    disable_input_buffering();

    /* since exactly one condition flag should be set at any given time, set the Z flag */
    reg[R_COND] = FL_ZRO;

    /* set the PC to starting position */
    /* 0x3000 is the default */
    enum { PC_START = 0x3000 };
    reg[R_PC] = PC_START;

    int running = 1;
    while (running)
    {
        /* FETCH */
        uint16_t instr = mem_read(reg[R_PC]++);
        uint16_t op = OP(instr);
        if (op == OP_RES || op == OP_RTI) {
            abort();
            break;
        }
        running = op_runners[op](instr);
        if (op != OP_TRAP) {
            running = 1;
        }

    }
    restore_input_buffering();
}