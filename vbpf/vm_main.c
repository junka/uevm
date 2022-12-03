#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include <gelf.h>
#include <libelf.h>

#include "log.h"
#include "vm.h"

static uint64_t reg[BPF_REG_MAX];

struct section {
    int num;
    struct ebpf_insn *ins;
};

struct section vm_section[1024];
int n_section = 0;

struct ext_call {
    char *name;
    ext_func func;
};

struct ext_call ecalls[256];
int n_ext_call;

int
register_ext_func(int id, char *name, ext_func func)
{
    ecalls[id].name = name;
    ecalls[id].func = func;
    return 0;
}

static int
lookup_xsym(const char *sn, size_t ofs, struct ebpf_insn *ins, size_t ins_sz)
{
    uint32_t idx, fidx;

    if (ofs % sizeof(ins[0]) != 0 || ofs >= ins_sz)
        return -1;

    idx = ofs / sizeof(ins[0]);
    int i = -1;
    for (i = 0; i < n_ext_call; i++) {
        if (strcmp(sn, ecalls[i].name) == 0) {
            fidx = i;
            break;
        }
    }

    log_info("code %x", ins[idx].code);

    if (ins[idx].code == (BPF_JMP | EBPF_CALL)) {
        /* for function we just need an index in our xsym table */
        /* we don't support multiple functions per BPF module,
            * so treat EBPF_PSEUDO_CALL to external function
            * as an ordinary EBPF_CALL.
            */
        if (ins[idx].src_reg == EBPF_PSEUDO_CALL) {
            log_info("(%u): "
                "EBPF_PSEUDO_CALL to external function: %s\n",
                idx, sn);
            ins[idx].src_reg = BPF_REG_0;
        }
        ins[idx].imm = fidx;
        log_info("imm %u", ins[idx].imm);
    } else if (ins[idx].code == (BPF_LD | BPF_IMM | EBPF_DW) &&
            ofs < ins_sz - sizeof(ins[idx])) {
        /* ignore maps handle here*/
        void *val = (void *)(uintptr_t)&stdout;
        /* for variable we need to store its absolute address */
        ins[idx].imm = (uintptr_t)val;
        ins[idx + 1].imm =
            (uint64_t)(uintptr_t)val >> 32;
        log_info("IMM ");
    } else {
        log_error("invalid ins in relocate section");
        return -1;
    }
    return 0;
}

#ifdef HAVE_ELF
int
ebpf_load_elf(const char *filename, const char *section)
{
    Elf *elf;
    Elf_Data *sd, *ed;
    Elf_Scn *scn = NULL;
    size_t sidx, eidx;
    int32_t rc;
    GElf_Ehdr ehdr;
    size_t shstrndx;
    int err = 0;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        log_info("fail to open file %s", filename);
        goto done;
    }
    elf_version(EV_CURRENT);
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        log_info("fail to open elf file");
        goto done;
    }
    if (!gelf_getehdr(elf, &ehdr)) {
        log_info("fail to read elf header");
        goto done;
    }

    if (ehdr.e_type != ET_REL && ehdr.e_type != ET_EXEC) {
        log_info("not a relocate or execute object e_type %d\n", ehdr.e_type);
        goto done;
    }

    if (elf_getshdrstrndx(elf, &shstrndx)) {
        log_info("fail to get index of the section name string table");
        goto done;
    }

    if (!elf_rawdata(elf_getscn(elf, shstrndx), NULL)) {
        log_info("fail to get raw data for first section");
        goto done;
    }

    /* walk through all sections */
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr sh;
        char *name;

        /* Get section header */
        if (gelf_getshdr(scn, &sh) != &sh) {
            log_warn("fail to get section header for %u", sh.sh_name);
            goto done;
        }
        name = elf_strptr(elf, shstrndx, sh.sh_name);
        if (!name) {
            log_warn("fail to get strptr for %u", sh.sh_name);
            goto done;
        }
        log_debug("get section name %s", name);
        if (!strcmp(name, BTF_ELF_SEC)) {
            Elf_Data *btf_data = elf_getdata(scn, 0);
            if (!btf_data) {
                log_warn("section .BTF with no data");
                goto done;
            }
            continue;
        } 
        // else if (btf_ext && !strcmp(name, BTF_EXT_ELF_SEC)) {
        //     Elf_Data *btf_ext_data = elf_getdata(scn, 0);
        //     if (!btf_ext_data) {
        //         goto done;
        //     }
        //     continue;
        // }

        if (!strcmp(name, "license")) {
            Elf_Data *license = elf_getdata(scn, NULL);
            log_info("License: %s", license->d_buf);
            continue;
        } else if (!strcmp(name, "version")) {
            continue;
        } else if (!strcmp(name, "maps")) {
            /* legacy map definition  */
            continue;
        }
        if (!strcmp(name, ".text")) {
            continue;
        } else if (!strcmp(name, ".data")) {
            continue;
        } else if (!strcmp(name, ".rodata")) {
            continue;
        } else if (!strncmp(name, ".debug", 6)) {
            /* skip all debug sections */
            continue;
        }
        if (sh.sh_type == SHT_PROGBITS &&
            sh.sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
            if (section && !strcmp(name, section)) {
                break;
            } else if (!section) {
                /* no section name specified, read all text */
                break;
            }
        }
    }

    /* read section data */
    sd = elf_getdata(scn, NULL);
    if (sd == NULL|| sd->d_size == 0 ||
        sd->d_size % sizeof(struct ebpf_insn) != 0) {
        err = elf_errno();
        log_warn("fail to read section data");
        goto done;
    }
    /* record the first section to process */
    ed = sd;
    eidx = elf_ndxscn(scn);

    switch (gelf_getclass(elf)) {
    case ELFCLASS32:
        log_debug("ELFCLASS32");
        break;
    case ELFCLASS64:
        log_debug("ELFCLASS64");
        break;
    default:
        break;
    }
    // vm_section[n_section].ins = ed->d_buf;
    vm_section[n_section].num = ed->d_size / sizeof(struct ebpf_insn);
    vm_section[n_section].ins = malloc(ed->d_size);
    memcpy(vm_section[n_section].ins, ed->d_buf, ed->d_size);
    n_section ++;

    /* iterate sections again to read reloc section */
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        Elf64_Shdr *shdr = elf64_getshdr(scn);
        if (shdr->sh_type != SHT_REL) {
            continue;
        } else if (shdr->sh_info != eidx) {
            continue;
        }

        /* relocation data for our code section */
        // elf_strptr(elf, shstrndx, shdr->sh_name);
        sd = elf_getdata(scn, NULL);
        if (!sd || sd->d_size == 0 ||
            sd->d_size % sizeof(Elf64_Rel) != 0) {
            log_info("fail to read section data");
            goto done;
        }
        Elf64_Rel *re = sd->d_buf;
        uint32_t n_rel = sd->d_size / sizeof(Elf64_Rel);
        size_t ofs, sym_id;
        /* sh_link is rel to section id sym table */
        Elf_Scn *re_scn = elf_getscn(elf, shdr->sh_link);
        sd = elf_getdata(re_scn, NULL);
        Elf64_Sym *sm = sd->d_buf;
        uint32_t n_sym = sd->d_size / sizeof(Elf64_Sym);
        char *sn;
        for (int i = 0; i < n_rel; i++) {
            ofs = re[i].r_offset;
            sym_id = ELF64_R_SYM(re[i].r_info);
            int rel_type = ELF64_R_TYPE(re[i].r_info);
            log_info("rel_type %d", rel_type);
            /* functions or maps */
            if (rel_type != 2 || rel_type != 1) {
                log_error("not support type %d", rel_type);
                continue;
            }
            if (sym_id >= n_sym) {
                log_info("sym idx too big");
                goto done;
            }
            sn = elf_strptr(elf, ehdr.e_shstrndx, sm[sym_id].st_name);
            log_info("sym name %s", sn);
            lookup_xsym(sn, ofs, vm_section[n_section-1].ins, ed->d_size);
        }
    }

done:
    if (elf) {
        elf_end(elf);
    }
    close(fd);
    return err;
}
#else
int
ebpf_load_raw(const char *filename, char *section)
{
    int err = -1;
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        log_error("fail to open file %s", filename);
        goto done;
    }
    int filesize = lseek(fd, 0, SEEK_END);
    if (err < 0) {
        goto done;
    }
    char* data = calloc(filesize, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = read(fd, data + offset, filesize - offset)) > 0) {
        offset += rv;
    }
    if (rv < 0) {
        free(data);
        goto done;
    }
    vm_section[n_section].num = filesize / sizeof(struct ebpf_insn);
    vm_section[n_section].ins = (struct ebpf_insn *)data;
done:
    close(fd);
    return err;
}
#endif
/* Programs with unreachable instructions and/or loops will be rejected.*/
int
ebpf_validate(struct ebpf_insn* insts, uint32_t num_insts)
{
    int32_t rc;

    if (num_insts >= BPF_MAX_INSTS) {
        log_error("too many instructions");
        return -1;
    }

    for (int i = 0; i < num_insts; i++) {
        struct ebpf_insn* ins = insts + i;
        bool store = false;
        switch(ins->code) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_IMM:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_NEG:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ARSH_REG:
            break;
        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (ins->imm != 16 && ins->imm != 32 && ins->imm != 64) {
                log_error("invalid endian immediate at PC %d", i);
                return -1;
            }
            break;
        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_NEG64:
        case EBPF_OP_MOD64_IMM:
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_ARSH64_REG:
            break;
        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            break;

        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            store = true;
            break;

        case EBPF_OP_LDDW:
            if (ins->src_reg != 0) {
                return -1;
            }
            if (i + 1 >= num_insts || insts[i + 1].code != 0) {
                return -1;
            }
            i++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JEQ32_REG:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGT32_REG:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JGE32_REG:
        case EBPF_OP_JSET32_REG:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JNE32_REG:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGT32_REG:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JSGE32_REG:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLT32_REG:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JLE32_REG:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLT32_REG:
        case EBPF_OP_JSLE32_IMM:
        case EBPF_OP_JSLE32_REG:
            if (ins->off == -1) {
                log_error("infinite loop at PC %d", i);
                return -1;
            }
            int new_pc = i + 1 + ins->off;
            if (new_pc < 0 || new_pc >= num_insts) {
                log_error("jump out of bounds at PC %d", i);
                return -1;
            } else if (insts[new_pc].code == 0) {
                log_error("jump to middle of lddw at PC %d", i);
                return -1;
            }
            break;

        case EBPF_OP_CALL:
            if (ins->imm < 0 || ins->imm >= 64) {
                log_error("invalid call immediate at PC %d", i);
                return -1;
            }
            if (!ecalls[ins->imm].func) {
                log_error("call to nonexistent function %u at PC %d", ins->imm, i);
                return -1;
            }
            break;

        case EBPF_OP_EXIT:
            break;
        default:
            return -1;
        }

        if (ins->src_reg >= BPF_REG_MAX) {
            return -1;
        }
        if (ins->dst_reg > BPF_REG_9 &&
            !(store && ins->dst_reg == BPF_REG_10)) {
            return -1;
        }
    }
    return 0;
}


#define MEM_LOAD(addr, type) (*(type *)addr)
#define MEM_STORE(addr, type, value) *(type *)(addr) = value

#define PROG_NAME "vbpf"
#define PROG_VERSION "0.0.1"

static void
usage()
{
    printf(PROG_NAME " options:\n");
}


extern int parse_options(int argc, const char * const *argv, void (*usage_cb)(), char *prog, char *version, char *path);

int main(int argc, const char *argv[])
{
    char path[1024];
    int ret = parse_options(argc, argv, usage, PROG_NAME, PROG_VERSION, path);
    if (ret) {
        exit(1);
    }
    if (path[0] == '\0') {
        printf("no valid object file\n");
        exit(1);
    }

#ifdef HAVE_ELF
    if (ebpf_load_elf(path, NULL)) {
#else
    if (ebpf_load_raw(path, NULL)) {
#endif
        printf("failed to load image: %s\n", path);
        exit(1);
     }

    struct ebpf_insn *insn = vm_section[0].ins;
    int num = vm_section[0].num;

    ebpf_validate(insn, num);

    uint16_t pc = 0;
    int running = 1;
    while (running) {
        uint16_t cur_pc = pc;
        struct ebpf_insn *insn = &vm_section[0].ins[pc ++];
        switch(insn->code) {
            case EBPF_OP_ADD64_IMM:
                reg[insn->dst_reg] += insn->imm;
                break;
            case EBPF_OP_ADD64_REG:
                reg[insn->dst_reg] += reg[insn->src_reg];
                break;
            case EBPF_OP_SUB64_IMM:
                reg[insn->dst_reg] -= insn->imm;
                break;
            case EBPF_OP_SUB64_REG:
                reg[insn->dst_reg] -= reg[insn->src_reg];
                break;
            case EBPF_OP_MUL64_IMM:
                reg[insn->dst_reg] *= insn->imm;
                break;
            case EBPF_OP_MUL64_REG:
                reg[insn->dst_reg] *= reg[insn->src_reg];
                break;
            case EBPF_OP_DIV64_IMM:
                reg[insn->dst_reg] /= insn->imm;
                break;
            case EBPF_OP_DIV64_REG:
                reg[insn->dst_reg] /= reg[insn->src_reg];
                break;
            case EBPF_OP_OR64_IMM:
                reg[insn->dst_reg] |= insn->imm;
                break;
            case EBPF_OP_OR64_REG:
                reg[insn->dst_reg] |= reg[insn->src_reg];
                break;
            case EBPF_OP_AND64_IMM:
                reg[insn->dst_reg] &= insn->imm;
                break;
            case EBPF_OP_AND64_REG:
                reg[insn->dst_reg] &= reg[insn->src_reg];
                break;
            case EBPF_OP_LSH64_IMM:
                reg[insn->dst_reg] <<= insn->imm;
                break;
            case EBPF_OP_LSH64_REG:
                reg[insn->dst_reg] <<= reg[insn->src_reg];
                break;
            case EBPF_OP_RSH64_IMM:
                reg[insn->dst_reg] >>= insn->imm;
                break;
            case EBPF_OP_RSH64_REG:
                reg[insn->dst_reg] >>= reg[insn->src_reg];
                break;
            case EBPF_OP_NEG64:
                reg[insn->dst_reg] = -reg[insn->dst_reg];
                break;
            case EBPF_OP_MOD64_IMM:
                reg[insn->dst_reg] %= insn->imm;
                break;
            case EBPF_OP_MOD64_REG:
                reg[insn->dst_reg] %= reg[insn->src_reg];
                break;
            case EBPF_OP_XOR64_IMM:
                reg[insn->dst_reg] ^= insn->imm;
                break;
            case EBPF_OP_XOR64_REG:
                reg[insn->dst_reg] ^= reg[insn->src_reg];
                break;
            case EBPF_OP_MOV64_IMM:
                reg[insn->dst_reg] = insn->imm;
                break;
            case EBPF_OP_MOV64_REG:
                reg[insn->dst_reg] = reg[insn->src_reg];
                break;
            case EBPF_OP_ARSH64_IMM:
                reg[insn->dst_reg] >>= insn->imm;
                break;
            case EBPF_OP_ARSH64_REG:
                reg[insn->dst_reg] >>= reg[insn->src_reg];
                break;
            /* 32 bit ops */
            case EBPF_OP_ADD_IMM:
                reg[insn->dst_reg] += insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_ADD_REG:
                reg[insn->dst_reg] += reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break; 
            case EBPF_OP_SUB_IMM:
                reg[insn->dst_reg] -= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_SUB_REG:
                reg[insn->dst_reg] -= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_MUL_IMM:
                reg[insn->dst_reg] *= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_MUL_REG:
                reg[insn->dst_reg] *= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_DIV_IMM:
                reg[insn->dst_reg] /= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_DIV_REG:
                reg[insn->dst_reg] /= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_OR_IMM:
                reg[insn->dst_reg] |= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_OR_REG:
                reg[insn->dst_reg] |= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_AND_IMM:
                reg[insn->dst_reg] &= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_AND_REG:
                reg[insn->dst_reg] &= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_LSH_IMM:
                reg[insn->dst_reg] <<= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_LSH_REG:
                reg[insn->dst_reg] <<= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_RSH_IMM:
                reg[insn->dst_reg] >>= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_RSH_REG:
                reg[insn->dst_reg] >>= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_NEG:
                reg[insn->dst_reg] = -reg[insn->dst_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_MOD_IMM:
                reg[insn->dst_reg] %= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_MOD_REG:
                reg[insn->dst_reg] %= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_XOR_IMM:
                reg[insn->dst_reg] ^= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_XOR_REG:
                reg[insn->dst_reg] ^= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_MOV_IMM:
                reg[insn->dst_reg] = insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_MOV_REG:
                reg[insn->dst_reg] = reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_ARSH_IMM:
                reg[insn->dst_reg] >>= insn->imm;
                reg[insn->dst_reg] &= UINT32_MAX;
                break;
            case EBPF_OP_ARSH_REG:
                reg[insn->dst_reg] >>= reg[insn->src_reg];
                reg[insn->dst_reg] &= UINT32_MAX;
                break;

            case EBPF_OP_LDDW:
                reg[insn->dst_reg] = insn->imm;
                break;
            case EBPF_OP_LDABSW:
                break;
            case EBPF_OP_LDABSH:
                break;
            case EBPF_OP_LDABSB:
                break;
            case EBPF_OP_LDABSDW:
                break;
            case EBPF_OP_LDINDW:
                break;
            case EBPF_OP_LDINDH:
                break;
            case EBPF_OP_LDINDB:
                break;
            case EBPF_OP_LDINDDW:
                break;

            case EBPF_OP_LDXW:
                reg[insn->dst_reg] = MEM_LOAD(reg[insn->src_reg] + insn->off, uint32_t);
                break;
            case EBPF_OP_LDXH:
                reg[insn->dst_reg] = MEM_LOAD(reg[insn->src_reg] + insn->off, uint16_t);
                break;
            case EBPF_OP_LDXB:
                reg[insn->dst_reg] = MEM_LOAD(reg[insn->src_reg] + insn->off, uint8_t);
                break;
            case EBPF_OP_LDXDW:
                reg[insn->dst_reg] = MEM_LOAD(reg[insn->src_reg] + insn->off, uint64_t);
                break;

            case EBPF_OP_STW:
                MEM_STORE(reg[insn->dst_reg] + insn->off, uint32_t, insn->imm);
                break;
            case EBPF_OP_STH:
                MEM_STORE(reg[insn->dst_reg] + insn->off, uint16_t, insn->imm);
                break;
            case EBPF_OP_STB:
                MEM_STORE(reg[insn->dst_reg] + insn->off, uint8_t, insn->imm);
                break;
            case EBPF_OP_STDW:
                MEM_STORE(reg[insn->dst_reg] + insn->off, uint64_t, insn->imm);
                break;
            case EBPF_OP_STXW:
                MEM_STORE(reg[insn->dst_reg] + insn->off, uint32_t, reg[insn->src_reg]);
                break;
            case EBPF_OP_STXH:
                MEM_STORE(reg[insn->dst_reg] + insn->off, uint16_t, reg[insn->src_reg]);
                break;
            case EBPF_OP_STXB:
                MEM_STORE(reg[insn->dst_reg] + insn->off, uint8_t, reg[insn->src_reg]);
                break;
            case EBPF_OP_STXDW:
                MEM_STORE(reg[insn->dst_reg] + insn->off, uint64_t, reg[insn->src_reg]);
                break;

            /* branch instruction */
            case EBPF_OP_JA:
                pc += insn->off;
                break;
            case EBPF_OP_JEQ_IMM:
                if (reg[insn->dst_reg] == insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JEQ_REG:
                if (reg[insn->dst_reg] == reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JGT_IMM:
                if (reg[insn->dst_reg] > insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JGT_REG:
                if (reg[insn->dst_reg] > reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JGE_IMM:
                if (reg[insn->dst_reg] >= insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JGE_REG:
                if (reg[insn->dst_reg] >= reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSET_IMM:
                if (reg[insn->dst_reg] & insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSET_REG:
                if (reg[insn->dst_reg] & reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JNE_IMM:
                if (reg[insn->dst_reg] != insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JNE_REG:
                if (reg[insn->dst_reg] != reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSGT_IMM:
                if (reg[insn->dst_reg] > insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSGT_REG:
                if (reg[insn->dst_reg] > reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSGE_IMM:
                if (reg[insn->dst_reg] >= insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSGE_REG:
                if (reg[insn->dst_reg] >= reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JLT_IMM:
                if (reg[insn->dst_reg] < insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JLT_REG:
                if (reg[insn->dst_reg] < reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JLE_IMM:
                if (reg[insn->dst_reg] <= insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JLE_REG:
                if (reg[insn->dst_reg] <= reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSLT_IMM:
                if (reg[insn->dst_reg] < insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSLT_REG:
                if (reg[insn->dst_reg] < reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSLE_IMM:
                if (reg[insn->dst_reg] <= insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSLE_REG:
                if (reg[insn->dst_reg] <= reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_CALL:
                // reg[0] = imm_funcs[insn->imm](reg[1], reg[2], reg[3], reg[4], reg[5]);
                break;

            /* 32bits branch */
            case EBPF_OP_JEQ32_IMM:
                if ((uint32_t)reg[insn->dst_reg] == (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JEQ32_REG:
                if ((uint32_t)reg[insn->dst_reg] == (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JGT32_IMM:
                if (reg[insn->dst_reg] > insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JGT32_REG:
                if (reg[insn->dst_reg] > reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JGE32_IMM:
                if ((uint32_t)reg[insn->dst_reg] >= (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JGE32_REG:
                if ((uint32_t)reg[insn->dst_reg] >= (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSET32_IMM:
                if ((uint32_t)reg[insn->dst_reg] & (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSET32_REG:
                if ((uint32_t)reg[insn->dst_reg] & (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JNE32_IMM:
                if ((uint32_t)reg[insn->dst_reg] != (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JNE32_REG:
                if ((uint32_t)reg[insn->dst_reg] != (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSGT32_IMM:
                if ((uint32_t)reg[insn->dst_reg] > (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSGT32_REG:
                if ((uint32_t)reg[insn->dst_reg] > (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSGE32_IMM:
                if ((uint32_t)reg[insn->dst_reg] >= (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSGE32_REG:
                if ((uint32_t)reg[insn->dst_reg] >= (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JLT32_IMM:
                if ((uint32_t)reg[insn->dst_reg] < (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JLT32_REG:
                if ((uint32_t)reg[insn->dst_reg] < (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JLE32_IMM:
                if ((uint32_t)reg[insn->dst_reg] <= (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JLE32_REG:
                if ((uint32_t)reg[insn->dst_reg] <= (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSLT32_IMM:
                if ((uint32_t)reg[insn->dst_reg] < (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSLT32_REG:
                if ((uint32_t)reg[insn->dst_reg] < (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSLE32_IMM:
                if ((uint32_t)reg[insn->dst_reg] <= (uint32_t)insn->imm) {
                    pc += insn->off;
                }
                break;
            case EBPF_OP_JSLE32_REG:
                if ((uint32_t)reg[insn->dst_reg] <= (uint32_t)reg[insn->src_reg]) {
                    pc += insn->off;
                }
                break;

            case EBPF_OP_EXIT:
                running = 0;
                break;
            default:
                break;
        }
    }
    log_info("return value %llu", reg[BPF_REG_0]);
    return 0;
}