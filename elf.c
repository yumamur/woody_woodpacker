#include "elf_utils.h"
#include <string.h>

void print_phdr64(Elf64_Phdr *ph)
{
	printf("{\n"
		   "  p_type   %s\n"
		   "  p_flags  %s\n"
		   "  p_offset %lu\n"
		   "  p_vaddr  %#0lX\n"
		   "  p_paddr  %#0lX\n"
		   "  p_filesz %lu\n"
		   "  p_memsz  %lu\n"
		   "  p_align  %lu\n"
		   "} Elf64_Phdr\n",
		   conv_p_type(ph->p_type),
		   conv_p_flags(ph->p_flags),
		   ph->p_offset,
		   ph->p_vaddr,
		   ph->p_paddr,
		   ph->p_filesz,
		   ph->p_memsz,
		   ph->p_align);
}

void print_phdr32(Elf32_Phdr *ph)
{
	printf("{\n"
		   "  p_type   = %s\n"
		   "  p_flags  = %s\n"
		   "  p_offset = %u\n"
		   "  p_vaddr  = %u\n"
		   "  p_paddr  = %0#x\n"
		   "  p_filesz = %0#x\n"
		   "  p_memsz  = %u\n"
		   "  p_align  = %u\n"
		   "} Elf32_Phdr\n",
		   conv_p_type(ph->p_type),
		   conv_p_flags(ph->p_flags),
		   ph->p_offset,
		   ph->p_vaddr,
		   ph->p_paddr,
		   ph->p_filesz,
		   ph->p_memsz,
		   ph->p_align);
}

struct s_data
{
	const char *name;
	uint64_t	val;
};

#define CASQT(name)                                                            \
	(struct s_data)                                                            \
	{                                                                          \
		#name, name                                                            \
	}

const char *conv_p_type(uint64_t type)
{
	static const struct s_data data[] = {
		CASQT(PT_NULL),		 CASQT(PT_LOAD),		 CASQT(PT_DYNAMIC),
		CASQT(PT_INTERP),	 CASQT(PT_NOTE),		 CASQT(PT_SHLIB),
		CASQT(PT_PHDR),		 CASQT(PT_TLS),			 CASQT(PT_NUM),
		CASQT(PT_LOOS),		 CASQT(PT_GNU_EH_FRAME), CASQT(PT_GNU_STACK),
		CASQT(PT_GNU_RELRO), CASQT(PT_GNU_PROPERTY), CASQT(PT_GNU_SFRAME),
		CASQT(PT_LOSUNW),	 CASQT(PT_SUNWBSS),		 CASQT(PT_SUNWSTACK),
		CASQT(PT_HISUNW),	 CASQT(PT_HIOS),		 CASQT(PT_LOPROC),
		CASQT(PT_HIPROC),
	};
	for (size_t i = 0; i < sizeof(data) / sizeof(data[0]); ++i)
	{
		if (data[i].val == type)
			return (data[i].name);
	}
	return ("UNKOWN");
}

const char *conv_p_flags(Elf32_Word flags)
{
	static char				   ret[255] = {};
	static const struct s_data data[] = {
		CASQT(PF_X),
		CASQT(PF_W),
		CASQT(PF_R),
	};
	ret[0] = 0;
	if (!flags)
	{
		strcpy(ret, "0x0");
		return ret;
	}
	size_t len = 0;
	for (size_t i = 0; i < sizeof(data) / sizeof(data[0]); ++i)
	{
		if (data[i].val & flags)
		{
			if (len)
				ret[len++] = '|';
			len += snprintf(ret + len, sizeof(ret) - len, "%s", data[i].name);
			flags &= ~data[i].val;
		}
	}
	if (flags & PF_MASKOS)
	{
		len += snprintf(ret + len,
						sizeof(ret) - len,
						"|%0#X",
						flags & PF_MASKOS);
		flags &= ~PF_MASKOS;
	}

	if (flags & PF_MASKPROC)
	{
		len += snprintf(ret + len,
						sizeof(ret) - len,
						"|%0#X",
						flags & PF_MASKPROC);
		flags &= ~PF_MASKPROC;
	}
	ret[len] = 0;
	return ret;
}

int is_valid_elf(const uint8_t *data, const size_t size)
{
	return (size >= EI_NIDENT && memcmp(data, ELFMAG, SELFMAG) == 0
			&& (data[EI_CLASS] == ELFCLASS32 || data[EI_CLASS] == ELFCLASS64)
			&& (data[EI_DATA] == ELFDATA2LSB || data[EI_DATA] == ELFDATA2MSB)
			&& data[EI_VERSION] == EV_CURRENT);
}