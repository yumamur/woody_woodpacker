#ifndef PE_UTILS_H
#define PE_UTILS_H

#include "woody.h" /* t_file, t_file_ops, DEFINE_STUB_PARAMS, ALIGN_*, in_bounds */

#include <stddef.h>
#include <stdint.h>

/*
 * Minimal, self-contained PE/COFF (Windows .exe) view, mirroring how
 * elf_utils.h sits beside the ELF logic. We target a Linux host, so there is no
 * <windows.h>: the handful of structures the packer actually touches are
 * declared here, packed and little-endian (PE is always little-endian).
 *
 * The container-agnostic packer core (t_file, t_file_ops, the stub param-block
 * layout, generic helpers) lives in woody.h and is shared with the ELF side;
 * this header adds only the PE-specific structures, the PE stub param layouts,
 * and the PE hook declarations. The payload transforms (ChaCha20, LZ4) are
 * format-agnostic and already live in main.c; only the container parsing and
 * the stub's runtime are PE-specific -- the PE stub makes no system or API
 * calls at all (the packer marks its section RWX), where the ELF stub drives
 * mprotect through syscalls.
 *
 * Layout references: PE32 / PE32+ as documented in the Microsoft PE format
 * spec. Field names follow the WinNT.h convention so they are greppable.
 */

#define PE_DOS_MAGIC 0x5A4D	   /* "MZ" */
#define PE_NT_MAGIC	 0x00004550 /* "PE\0\0" */

#define PE_OPT_MAGIC_PE32	0x010B /* 32-bit image */
#define PE_OPT_MAGIC_PE32P	0x020B /* 64-bit image (PE32+) */

#define PE_MACHINE_I386	 0x014C
#define PE_MACHINE_AMD64 0x8664

/* IMAGE_SECTION_HEADER.Characteristics bits we care about */
#define PE_SCN_CNT_CODE		  0x00000020
#define PE_SCN_MEM_EXECUTE	  0x20000000
#define PE_SCN_MEM_READ		  0x40000000
#define PE_SCN_MEM_WRITE	  0x80000000

#define PE_SIZEOF_SHORT_NAME 8

#pragma pack(push, 1)

/* The legacy DOS stub header. Only e_magic and e_lfanew matter to us:
 * e_lfanew is the file offset of the PE signature + COFF header. */
typedef struct s_pe_dos_header
{
	uint16_t e_magic;	 /* must be PE_DOS_MAGIC ("MZ") */
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	uint32_t e_lfanew;	 /* file offset of IMAGE_NT_HEADERS */
} t_pe_dos_header;

/* COFF file header (same in PE32 and PE32+). */
typedef struct s_pe_file_header
{
	uint16_t Machine;			  /* PE_MACHINE_* */
	uint16_t NumberOfSections;	  /* how many IMAGE_SECTION_HEADER follow */
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader; /* bytes of optional header that follow */
	uint16_t Characteristics;
} t_pe_file_header;

typedef struct s_pe_data_directory
{
	uint32_t VirtualAddress;
	uint32_t Size;
} t_pe_data_directory;

/*
 * The optional header differs between PE32 and PE32+ only in the width of a few
 * address fields (ImageBase, stack/heap reserves). We read the common prefix
 * through PE_OPT_MAGIC first, then pick the right layout -- the same class
 * branch the ELF side does on ELFCLASS32/64.
 */
typedef struct s_pe_opt_header32
{
	uint16_t Magic;			  /* PE_OPT_MAGIC_PE32 */
	uint8_t	 MajorLinkerVersion;
	uint8_t	 MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint; /* RVA of the entry point */
	uint32_t BaseOfCode;
	uint32_t BaseOfData;		  /* PE32 only (absent in PE32+) */
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	/* data directories follow */
} t_pe_opt_header32;

typedef struct s_pe_opt_header64
{
	uint16_t Magic;			  /* PE_OPT_MAGIC_PE32P */
	uint8_t	 MajorLinkerVersion;
	uint8_t	 MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint; /* RVA of the entry point */
	uint32_t BaseOfCode;		  /* no BaseOfData in PE32+ */
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	/* data directories follow */
} t_pe_opt_header64;

/* One entry of the section table -- the PE loader view, the analogue of an
 * ELF program header. PointerToRawData/SizeOfRawData give the bytes on disk
 * (what we would encrypt); VirtualAddress is the RVA where it maps. */
typedef struct s_pe_section_header
{
	uint8_t	 Name[PE_SIZEOF_SHORT_NAME];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;	  /* RVA */
	uint32_t SizeOfRawData;		  /* bytes on disk */
	uint32_t PointerToRawData;	  /* file offset of those bytes */
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;	  /* PE_SCN_* */
} t_pe_section_header;

#pragma pack(pop)

/* Parsed, bounds-checked view of a PE image. Mirrors t_file's role for ELF:
 * every pointer aliases into the caller's mmap'd buffer, so nothing is copied
 * or owned. */
typedef struct s_pe
{
	const uint8_t			  *data;
	size_t					   size;
	int						   is64;	 /* PE32+ (1) vs PE32 (0) */
	const t_pe_file_header	  *fh;
	const void				  *opt;		 /* -> opt_header32/64 by is64 */
	const t_pe_section_header *sections; /* fh->NumberOfSections entries */
	uint32_t				   entry_rva;
	uint64_t				   image_base;
} t_pe;

/* Cheap signature probe: "MZ" ... "PE\0\0". Does not fully validate; callers
 * that go on to read structures use pe_parse(), which bounds-checks. */
int pe_detect(const uint8_t *data, size_t size);

/* Fully parse and bounds-check the headers + section table into `out`.
 * Returns 0 on success, -1 on any malformed/out-of-bounds field. */
int pe_parse(const uint8_t *data, size_t size, t_pe *out);

/* Dump the headers and section table, and point out the section that holds the
 * entry point -- the region the packer encrypts. Returns 0/-1. */
int pe_inspect(const uint8_t *data, size_t size);

/* PE32+ (x64) stub: identical 8-byte layout to the ELF64 stub -- the param
 * block is the same magic + five delta/length fields + key + nonce, only the
 * deltas are RVA differences instead of file-offset differences. */
DEFINE_STUB_PARAMS(STUBPE, 8);

/* PE32 (x86) stub: 4-byte deltas/lengths. */
DEFINE_STUB_PARAMS(STUBPE32, 4);

/* PE (.exe) packing shares the main.c pipeline through PE-specific hooks (pe.c):
 * pe_prepare() fills f->is64 (PE32+ vs PE32), pe_select_ops() hands back the
 * matching t_file_ops table; the already-packed check is that table's hook. */
const t_file_ops *pe_select_ops(const t_file *f);
int				  pe_prepare(t_file *f);

#endif
