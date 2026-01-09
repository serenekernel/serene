#include <stdint.h>

typedef struct {
    unsigned char e_ident[16]; /* Magic number and other info */
    uint16_t e_type; /* Object file type */
    uint16_t e_machine; /* Architecture */
    uint32_t e_version; /* Object file version */
    uint64_t e_entry; /* Entry point virtual address */
    uint64_t e_phoff; /* Program header table file offset */
    uint64_t e_shoff; /* Section header table file offset */
    uint32_t e_flags; /* Processor-specific flags */
    uint16_t e_ehsize; /* ELF header size in bytes */
    uint16_t e_phentsize; /* Program header table entry size */
    uint16_t e_phnum; /* Program header table entry count */
    uint16_t e_shentsize; /* Section header table entry size */
    uint16_t e_shnum; /* Section header table entry count */
    uint16_t e_shstrndx; /* Section header string table index */
} elf64_elf_header_t;

#define ELF_CLASS_IDX 4
#define ELF_CLASS_64_BIT 2

#define ELF_DATA_IDX 5
#define ELF_DATA_2LSB 1

#define ETYPE_REL 1
#define ETYPE_EXEC 2
#define ETYPE_DYN 3

#define EMACHINE_X86_64 62

typedef struct {
    uint32_t p_type; /* Segment type */
    uint32_t p_flags; /* Segment flags */
    uint64_t p_offset; /* Segment file offset */
    uint64_t p_vaddr; /* Segment virtual address */
    uint64_t p_paddr; /* Segment physical address */
    uint64_t p_filesz; /* Segment size in file */
    uint64_t p_memsz; /* Segment size in memory */
    uint64_t p_align; /* Segment alignment */
} elf64_program_header_t;

#define PTYPE_LOAD 1 /* Loadable program segment */
#define PFLAGS_EXECUTE (1 << 0) /* Segment is executable */
#define PFLAGS_WRITE (1 << 1) /* Segment is writable */
