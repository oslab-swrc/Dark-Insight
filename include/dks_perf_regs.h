#ifndef _DKS_PERF_REGS_H
#define _DKS_PERF_REGS_H

#include <arch/x86/include/perf_regs.h>

#ifdef CONFIG_X86_32
#define PERF_REG_X86_MAX PERF_REG_X86_32_MAX
#else
#define PERF_REG_X86_MAX PERF_REG_X86_64_MAX
#endif

#define REGNAME_MAPPING(n, b, w) { .name = #n, .perf_offset = (b), .reg_width=(w) }
#define REGNAME_MAPPING_END { .name = NULL }

#define PT_REGS_OFFSET(id, r) [id] = offsetof(struct pt_regs, r)

enum reg_width{
	X86_REG_LOW=0,
	X86_REG_HIGH,
	X86_REG_WORD,
	X86_REG_DWORD,
	X86_REG_QWORD,
	X86_REG_WIDTH_MAX
};

struct regname_offset{
	const char *name;
	__u8 perf_offset; 	 /*offset_of pt_regs*/
	enum reg_width reg_width;/*register width*/
};

/*x86_64 register layout*/
union x86_64_reg{
	__u64 q;  /*64bit*/
	__u32 d;  /*32bit*/
	__u16 w;
	__u8  b[2];
};

extern const struct regname_offset regname_to_perf_reg[];
/*return index of regname_offset list*/
__u16 perf_regs__regname_to_offset(const char* regname);

#endif /* _DKS_PERF_REGS_H */
