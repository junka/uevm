#ifndef _BPF_VM_H_
#define _BPF_VM_H_

#ifdef __cplusplus
extern "C" {
#endif

enum register_type {
    BPF_REG_0 = 0,  /* return value from internal function/for eBPF program */
    BPF_REG_1,      /* reg 1 - 5 is argurment 0 - 4 for function */
    BPF_REG_2,
    BPF_REG_3,
    BPF_REG_4,
    BPF_REG_5,
    BPF_REG_6,      /* reg 6- 9 callee save register*/
    BPF_REG_7,
    BPF_REG_8,
    BPF_REG_9,
    BPF_REG_10,     /* stack pointer, read-only */
    BPF_REG_MAX
};

#define EBPF_PSEUDO_CALL BPF_REG_1

/*
msb                                                        lsb
+------------------------+----------------+----+----+--------+
|immediate               |offset          |src |dst |opcode  |
+------------------------+----------------+----+----+--------+
*/

struct ebpf_insn {
    uint8_t code;        /* opcode */
    uint8_t dst_reg:4;   /* dest register */
    uint8_t src_reg:4;   /* source register */
    int16_t off;        /* signed offset */
    int32_t imm;        /* signed immediate constant */
};

/* least 3 bits */
#define BPF_CLASS(code) ((code)&0x7)
enum bpf_ins_class {
    BPF_LD = 0,
    BPF_LDX = 1,
    BPF_ST = 2,
    BPF_STX = 3,
    BPF_ALU = 4,
    BPF_JMP = 5,
    BPF_RET = 6,
    BPF_MISC = 7,
    EBPF_ALU64 = BPF_MISC,
};

/* LD/LDX/ST/STX opcode structure: |mde|sz|cls| */
/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define	BPF_W       0x00
#define	BPF_H       0x08
#define	BPF_B       0x10
#define	EBPF_DW     0x18

#define BPF_MODE(code)  ((code) & 0xe0)
#define BPF_IMM     0x0
#define	BPF_ABS     0x20
#define	BPF_IND     0x40
#define	BPF_MEM     0x60
#define	BPF_LEN     0x80
#define	BPF_MSH     0xa0

#define EBPF_XADD   0xc0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define BPF_OP_ENUM(e)  (e << 4)
enum bpf_alu_op_fileds {
    BPF_ADD = BPF_OP_ENUM(0),   /* += */
    BPF_SUB = BPF_OP_ENUM(1),   /* -= */
    BPF_MUL = BPF_OP_ENUM(2),   /* *= */
    BPF_DIV = BPF_OP_ENUM(3),   /* /= */
    BPF_OR  = BPF_OP_ENUM(4),   /* |= */
    BPF_AND = BPF_OP_ENUM(5),   /* &= */
    BPF_LSH = BPF_OP_ENUM(6),   /* <<= */
    BPF_RSH = BPF_OP_ENUM(7),   /* >>= */
    BPF_NEG = BPF_OP_ENUM(8),   /* = - */
    BPF_MOD = BPF_OP_ENUM(9),   /* %= */
    BPF_XOR = BPF_OP_ENUM(10),  /* ^= */
    EBPF_MOV = BPF_OP_ENUM(11), /* = */
    EBPF_ARSH = BPF_OP_ENUM(12),/* >>= (arithmetic)*/
    EBPF_END = BPF_OP_ENUM(13),
};

enum bpf_jmp_op_fileds {
    BPF_JA = BPF_OP_ENUM(0),
    BPF_JEQ = BPF_OP_ENUM(1),
    BPF_JGT = BPF_OP_ENUM(2),
    BPF_JGE = BPF_OP_ENUM(3),
    BPF_JSET = BPF_OP_ENUM(4),
    EBPF_JNE = BPF_OP_ENUM(5),
    EBPF_JSGT = BPF_OP_ENUM(6),
    EBPF_JSGE = BPF_OP_ENUM(7),
    EBPF_CALL = BPF_OP_ENUM(8),
    EBPF_EXIT = BPF_OP_ENUM(9),
    EBPF_JLT = BPF_OP_ENUM(10),
    EBPF_JLE = BPF_OP_ENUM(11),
    EBPF_JSLT = BPF_OP_ENUM(12),
    EBPF_JSLE = BPF_OP_ENUM(13),
};

//
#define BPF_SRC(code)   ((code) & 0x08)
#define	BPF_K       0x00    /* s as imm */
#define	BPF_X       0x08    /* s as src */


/* ALU/ALU64/JMP opcode structure: |op  |s|cls| */
#define EBPF_ALU_OP(op, source, class) (op | source | class)

/* if BPF_OP(code) == EBPF_END */
#define EBPF_TO_LE 0x00  /* convert to little-endian */
#define EBPF_TO_BE 0x08  /* convert to big-endian */


/* https://github.com/iovisor/bpf-docs/blob/master/eBPF.md */
/* ALU Instructions */
#define ALU64_OP(op, s) EBPF_ALU_OP(op, s, EBPF_ALU64)
#define ALU64_IMM(op) ALU64_OP(op, BPF_K)
#define ALU64_REG(op) ALU64_OP(op, BPF_X)

#define EBPF_OP_ADD64_IMM ALU64_IMM(BPF_ADD)
#define EBPF_OP_ADD64_REG ALU64_REG(BPF_ADD)
#define EBPF_OP_SUB64_IMM ALU64_IMM(BPF_SUB)
#define EBPF_OP_SUB64_REG ALU64_REG(BPF_SUB)
#define EBPF_OP_MUL64_IMM ALU64_IMM(BPF_MUL)
#define EBPF_OP_MUL64_REG ALU64_REG(BPF_MUL)
#define EBPF_OP_DIV64_IMM ALU64_IMM(BPF_DIV)
#define EBPF_OP_DIV64_REG ALU64_REG(BPF_DIV)
#define EBPF_OP_OR64_IMM  ALU64_IMM(BPF_OR)
#define EBPF_OP_OR64_REG  ALU64_REG(BPF_OR)
#define EBPF_OP_AND64_IMM ALU64_IMM(BPF_AND)
#define EBPF_OP_AND64_REG ALU64_REG(BPF_AND)
#define EBPF_OP_LSH64_IMM ALU64_IMM(BPF_LSH)
#define EBPF_OP_LSH64_REG ALU64_REG(BPF_LSH)
#define EBPF_OP_RSH64_IMM ALU64_IMM(BPF_RSH)
#define EBPF_OP_RSH64_REG ALU64_REG(BPF_RSH)
#define EBPF_OP_NEG64     ALU64_IMM(BPF_NEG)
#define EBPF_OP_MOD64_IMM ALU64_IMM(BPF_MOD)
#define EBPF_OP_MOD64_REG ALU64_REG(BPF_MOD)
#define EBPF_OP_XOR64_IMM ALU64_IMM(BPF_XOR)
#define EBPF_OP_XOR64_REG ALU64_REG(BPF_XOR)
#define EBPF_OP_MOV64_IMM ALU64_IMM(EBPF_MOV)
#define EBPF_OP_MOV64_REG ALU64_REG(EBPF_MOV)
#define EBPF_OP_ARSH64_IMM ALU64_IMM(EBPF_ARSH)
#define EBPF_OP_ARSH64_REG ALU64_REG(EBPF_ARSH)

/* 32 bit ops, These instructions use only the lower 32 bits of their operands
 and zero the upper 32 bits of the destination register.*/
#define ALU32_OP(op, s) EBPF_ALU_OP(op, s, BPF_ALU)
#define ALU32_IMM(op) ALU32_OP(op, BPF_K)
#define ALU32_REG(op) ALU32_OP(op, BPF_X)

#define EBPF_OP_ADD_IMM ALU32_IMM(BPF_ADD)
#define EBPF_OP_ADD_REG ALU32_REG(BPF_ADD)
#define EBPF_OP_SUB_IMM ALU32_IMM(BPF_SUB)
#define EBPF_OP_SUB_REG ALU32_REG(BPF_SUB)
#define EBPF_OP_MUL_IMM ALU32_IMM(BPF_MUL)
#define EBPF_OP_MUL_REG ALU32_REG(BPF_MUL)
#define EBPF_OP_DIV_IMM ALU32_IMM(BPF_DIV)
#define EBPF_OP_DIV_REG ALU32_REG(BPF_DIV)
#define EBPF_OP_OR_IMM  ALU32_IMM(BPF_OR)
#define EBPF_OP_OR_REG  ALU32_REG(BPF_OR)
#define EBPF_OP_AND_IMM ALU32_IMM(BPF_AND)
#define EBPF_OP_AND_REG ALU32_REG(BPF_AND)
#define EBPF_OP_LSH_IMM ALU32_IMM(BPF_LSH)
#define EBPF_OP_LSH_REG ALU32_REG(BPF_LSH)
#define EBPF_OP_RSH_IMM ALU32_IMM(BPF_RSH)
#define EBPF_OP_RSH_REG ALU32_REG(BPF_RSH)
#define EBPF_OP_NEG     ALU32_IMM(BPF_NEG)
#define EBPF_OP_MOD_IMM ALU32_IMM(BPF_MOD)
#define EBPF_OP_MOD_REG ALU32_REG(BPF_MOD)
#define EBPF_OP_XOR_IMM ALU32_IMM(BPF_XOR)
#define EBPF_OP_XOR_REG ALU32_REG(BPF_XOR)
#define EBPF_OP_MOV_IMM ALU32_IMM(EBPF_MOV)
#define EBPF_OP_MOV_REG ALU32_REG(EBPF_MOV)
#define EBPF_OP_ARSH_IMM ALU32_IMM(EBPF_ARSH)
#define EBPF_OP_ARSH_REG ALU32_REG(EBPF_ARSH)

/* byteswap instructions */
#define END_OP(op, s) EBPF_ALU_OP(op, s, EBPF_END)
#define EBPF_OP_LE END_OP(EBPF_TO_LE, BPF_K)
#define EBPF_OP_BE END_OP(EBPF_TO_BE, BPF_K)
#define EBPF_OP_LE16 EBPF_OP_LE  /* imm == 16 */
#define EBPF_OP_LE32 EBPF_OP_LE  /* imm == 32 */
#define EBPF_OP_LE64 EBPF_OP_LE  /* imm == 64 */
#define EBPF_OP_BE16 EBPF_OP_BE  /* imm == 16 */
#define EBPF_OP_BE32 EBPF_OP_BE  /* imm == 32 */
#define EBPF_OP_BE64 EBPF_OP_BE  /* imm == 64 */


#define EBPF_LD_OP(mde, sz, cls) (mde | sz | cls)
/* Memory Instructions */
#define MEM_OP_LD(mde, sz) EBPF_LD_OP(mde, sz, BPF_LD)
#define EBPF_OP_LDDW     MEM_OP_LD(BPF_IMM, EBPF_DW)
#define EBPF_OP_LDABSW   MEM_OP_LD(BPF_ABS, BPF_W)
#define EBPF_OP_LDABSH   MEM_OP_LD(BPF_ABS, BPF_H)
#define EBPF_OP_LDABSB   MEM_OP_LD(BPF_ABS, BPF_B)
#define EBPF_OP_LDABSDW  MEM_OP_LD(BPF_ABS, EBPF_DW)
#define EBPF_OP_LDINDW   MEM_OP_LD(BPF_IND, BPF_W)
#define EBPF_OP_LDINDH   MEM_OP_LD(BPF_IND, BPF_H)
#define EBPF_OP_LDINDB   MEM_OP_LD(BPF_IND, BPF_B)
#define EBPF_OP_LDINDDW  MEM_OP_LD(BPF_IND, EBPF_DW)

#define MEM_OP_LDX(sz) EBPF_LD_OP(BPF_MEM, sz, BPF_LDX)
#define EBPF_OP_LDXW     MEM_OP_LDX(BPF_W)
#define EBPF_OP_LDXH     MEM_OP_LDX(BPF_H)
#define EBPF_OP_LDXB     MEM_OP_LDX(BPF_B)
#define EBPF_OP_LDXDW    MEM_OP_LDX(EBPF_DW)

#define MEM_OP_ST(sz) EBPF_LD_OP(BPF_MEM, sz, BPF_ST)
#define EBPF_OP_STW      MEM_OP_ST(BPF_W)
#define EBPF_OP_STH      MEM_OP_ST(BPF_H)
#define EBPF_OP_STB      MEM_OP_ST(BPF_B)
#define EBPF_OP_STDW     MEM_OP_ST(EBPF_DW)

#define MEM_OP_STX(sz)  EBPF_LD_OP(BPF_MEM, sz, BPF_STX)
#define EBPF_OP_STXW     MEM_OP_STX(BPF_W)
#define EBPF_OP_STXH     MEM_OP_STX(BPF_H)
#define EBPF_OP_STXB     MEM_OP_STX(BPF_B)
#define EBPF_OP_STXDW    MEM_OP_STX(EBPF_DW)

/* branch instructions */
#define BRANCH_OP(op, s) EBPF_ALU_OP(op, s, BPF_JMP)
#define BRANCH_OP_IMM(op) BRANCH_OP(op, BPF_K)
#define BRANCH_OP_REG(op) BRANCH_OP(op, BPF_X)

#define EBPF_OP_JA       BRANCH_OP_IMM(BPF_JA)
#define EBPF_OP_JEQ_IMM  BRANCH_OP_IMM(BPF_JEQ)
#define EBPF_OP_JEQ_REG  BRANCH_OP_REG(BPF_JEQ)
#define EBPF_OP_JGT_IMM  BRANCH_OP_IMM(BPF_JGT)
#define EBPF_OP_JGT_REG  BRANCH_OP_REG(BPF_JGT)
#define EBPF_OP_JGE_IMM  BRANCH_OP_IMM(BPF_JGE)
#define EBPF_OP_JGE_REG  BRANCH_OP_REG(BPF_JGE)
#define EBPF_OP_JSET_IMM BRANCH_OP_IMM(BPF_JSET)
#define EBPF_OP_JSET_REG BRANCH_OP_REG(BPF_JSET)
#define EBPF_OP_JNE_IMM  BRANCH_OP_IMM(EBPF_JNE)
#define EBPF_OP_JNE_REG  BRANCH_OP_REG(EBPF_JNE)
#define EBPF_OP_JSGT_IMM BRANCH_OP_IMM(EBPF_JSGT)
#define EBPF_OP_JSGT_REG BRANCH_OP_REG(EBPF_JSGT)
#define EBPF_OP_JSGE_IMM BRANCH_OP_IMM(EBPF_JSGE)
#define EBPF_OP_JSGE_REG BRANCH_OP_REG(EBPF_JSGE)
#define EBPF_OP_CALL     BRANCH_OP_IMM(EBPF_CALL)
#define EBPF_OP_EXIT     BRANCH_OP_IMM(EBPF_EXIT)
#define EBPF_OP_JLT_IMM  BRANCH_OP_IMM(EBPF_JLT)
#define EBPF_OP_JLT_REG  BRANCH_OP_REG(EBPF_JLT)
#define EBPF_OP_JLE_IMM  BRANCH_OP_IMM(EBPF_JLE)
#define EBPF_OP_JLE_REG  BRANCH_OP_REG(EBPF_JLE)
#define EBPF_OP_JSLT_IMM BRANCH_OP_IMM(EBPF_JSLT)
#define EBPF_OP_JSLT_REG BRANCH_OP_REG(EBPF_JSLT)
#define EBPF_OP_JSLE_IMM BRANCH_OP_IMM(EBPF_JSLE)
#define EBPF_OP_JSLE_REG BRANCH_OP_REG(EBPF_JSLE)

#define BRANCH32_OP(op, s) EBPF_ALU_OP(op, s, BPF_RET)
#define BRANCH32_OP_IMM(op) BRANCH32_OP(op, BPF_K)
#define BRANCH32_OP_REG(op) BRANCH32_OP(op, BPF_X)

#define EBPF_OP_JEQ32_IMM  BRANCH32_OP_IMM(BPF_JEQ)
#define EBPF_OP_JEQ32_REG  BRANCH32_OP_REG(BPF_JEQ)
#define EBPF_OP_JGT32_IMM  BRANCH32_OP_IMM(BPF_JGT)
#define EBPF_OP_JGT32_REG  BRANCH32_OP_REG(BPF_JGT)
#define EBPF_OP_JGE32_IMM  BRANCH32_OP_IMM(BPF_JGE)
#define EBPF_OP_JGE32_REG  BRANCH32_OP_REG(BPF_JGE)
#define EBPF_OP_JSET32_IMM BRANCH32_OP_IMM(BPF_JSET)
#define EBPF_OP_JSET32_REG BRANCH32_OP_REG(BPF_JSET)
#define EBPF_OP_JNE32_IMM  BRANCH32_OP_IMM(EBPF_JNE)
#define EBPF_OP_JNE32_REG  BRANCH32_OP_REG(EBPF_JNE)
#define EBPF_OP_JSGT32_IMM BRANCH32_OP_IMM(EBPF_JSGT)
#define EBPF_OP_JSGT32_REG BRANCH32_OP_REG(EBPF_JSGT)
#define EBPF_OP_JSGE32_IMM BRANCH32_OP_IMM(EBPF_JSGE)
#define EBPF_OP_JSGE32_REG BRANCH32_OP_REG(EBPF_JSGE)
#define EBPF_OP_JLT32_IMM  BRANCH32_OP_IMM(EBPF_JLT)
#define EBPF_OP_JLT32_REG  BRANCH32_OP_REG(EBPF_JLT)
#define EBPF_OP_JLE32_IMM  BRANCH32_OP_IMM(EBPF_JLE)
#define EBPF_OP_JLE32_REG  BRANCH32_OP_REG(EBPF_JLE)
#define EBPF_OP_JSLT32_IMM BRANCH32_OP_IMM(EBPF_JSLT)
#define EBPF_OP_JSLT32_REG BRANCH32_OP_REG(EBPF_JSLT)
#define EBPF_OP_JSLE32_IMM BRANCH32_OP_IMM(EBPF_JSLE)
#define EBPF_OP_JSLE32_REG BRANCH32_OP_REG(EBPF_JSLE)

#define BTF_ELF_SEC ".BTF"
#define BTF_EXT_ELF_SEC ".BTF.ext"
#define MAPS_ELF_SEC ".maps"

#define BPF_MAX_INSTS 65535


typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);


#ifdef __cplusplus
}
#endif

#endif /*_BPF_VM_H_*/