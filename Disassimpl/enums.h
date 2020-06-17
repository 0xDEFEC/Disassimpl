#include <string>

// exit codes for exit()
enum opcodes {
	CODE_FILEINACCESSIBLE = 1,
	CODE_FILENOTFOUND,
	CODE_ISDRIECTORY,
	CODE_HELPREQUEST,
	CODE_PY_MODIMPORTFAILURE,
	CODE_PY_SYMIMPORTFAILURE,
	CODE_PY_CALLBACKFAILURE
};

// available archs to be passed to Python by the user
enum arch_options {
	ARCH_ARM,
	ARCH_ARM64,
	ARCH_MIPS,
	ARCH_X86,
	ARCH_PPC,
	ARCH_SPARC,
	ARCH_SYSZ,
	ARCH_XCORE,
	ARCH_M68K,
	ARCH_TMS320C64X,
	ARCH_M680X,
	ARCH_EVM,
	// ARCH_MAX -> don't know wtf ARCH_MAX is - it isn't in the CS C API, so... not gonna use it
	ARCH_ALL = 0xFFFF
}; uint16_t parseArch(std::string arch) {
	if (arch == "ARM")        { return 0;      }
	if (arch == "ARM64")      { return 1;      }
	if (arch == "MIPS")       { return 2;      }
	if (arch == "X86")        { return 3;      }
	if (arch == "PPC")        { return 4;      }
	if (arch == "SPARC")      { return 5;      }
	if (arch == "SYSZ")       { return 6;      }
	if (arch == "XCORE")      { return 7;      }
	if (arch == "M68K")       { return 8;      }
	if (arch == "TMS320C64X") { return 9;      }
	if (arch == "M680X")      { return 10;     }
	if (arch == "EVM")        { return 11;     }
	if (arch == "ALL")        { return 0xFFFF; }
	else                      { return 3;      } // default to X86
}

// available modes to be passed by user to Python
enum mode_options {
	MODE_LITTLE_ENDIAN = 0,           // little - endian mode(default mode)
	MODE_ARM           = 0,           // ARM mode
	MODE_16            = (1 << 1),    // 16 - bit mode(for X86)
	MODE_32            = (1 << 2),    // 32 - bit mode(for X86)
	MODE_64            = (1 << 3),    // 64 - bit mode(for X86, PPC)
	MODE_THUMB         = (1 << 4),    // ARM's Thumb mode, including Thumb-2
	MODE_MCLASS        = (1 << 5),    // ARM's Cortex-M series
	MODE_V8            = (1 << 6),    // ARMv8 A32 encodings for ARM
	MODE_V9            = (1 << 4),    // Sparc V9 mode(for Sparc)
	MODE_MICRO         = (1 << 4),    // MicroMips mode(MIPS architecture)
	MODE_MIPS3         = (1 << 5),    // Mips III ISA
	MODE_MIPS32R6      = (1 << 6),    // Mips32r6 ISA
	MODE_MIPS2         = (1 << 7),    // Mips II ISA
	MODE_QPX           = (1 << 4),    // Quad Processing eXtensions mode(PPC)
	MODE_M68K_000      = (1 << 1),    // M68K 68000 mode
	MODE_M68K_010      = (1 << 2),    // M68K 68010 mode
	MODE_M68K_020      = (1 << 3),    // M68K 68020 mode
	MODE_M68K_030      = (1 << 4),    // M68K 68030 mode
	MODE_M68K_040      = (1 << 5),    // M68K 68040 mode
	MODE_M68K_060      = (1 << 6),    // M68K 68060 mode
	MODE_BIG_ENDIAN    = (1 << 31),   // Big-endian mode
	MODE_MIPS32        = MODE_32,     // Mips32 ISA
	MODE_MIPS64        = MODE_64,     // Mips64 ISA
	MODE_M680X_6301    = (1 << 1),    // M680X HD6301 / 3 mode
	MODE_M680X_6309    = (1 << 2),    // M680X HD6309 mode
	MODE_M680X_6800    = (1 << 3),    // M680X M6800 / 2 mode
	MODE_M680X_6801    = (1 << 4),    // M680X M6801 / 3 mode
	MODE_M680X_6805    = (1 << 5),    // M680X M6805 mode
	MODE_M680X_6808    = (1 << 6),    // M680X M68HC08 mode
	MODE_M680X_6809    = (1 << 7),    // M680X M6809 mode
	MODE_M680X_6811    = (1 << 8),    // M680X M68HC11 mode
	MODE_M680X_CPU12   = (1 << 9),    // M680X CPU12 mode
	MODE_M680X_HCS08   = (1 << 10)    // M680X HCS08 mode
}; uint8_t parseMode(std::string mode) {
	if (mode == "LEM")         { return 0;  }
	if (mode == "ARM")         { return 1;  }
	if (mode == "16")          { return 2;  }
	if (mode == "32")          { return 3;  }
	if (mode == "64")          { return 4;  }
	if (mode == "THUMB")       { return 5;  }
	if (mode == "MCLASS")      { return 6;  }
	if (mode == "V8")          { return 7;  }
	if (mode == "V9")          { return 8;  }
	if (mode == "MICRO")       { return 9;  }
	if (mode == "MIPS3")       { return 10; }
	if (mode == "MIPS2")       { return 11; }
	if (mode == "MIPS32R6")    { return 12; }
	if (mode == "QPX")         { return 13; }
	if (mode == "M68K000")     { return 14; }
	if (mode == "M68K010")     { return 15; }
	if (mode == "M68K020")     { return 16; }
	if (mode == "M68K030")     { return 17; }
	if (mode == "M68K040")     { return 18; }
	if (mode == "M68K060")     { return 19; }
	if (mode == "BEM")         { return 20; }
	if (mode == "MIPS32")      { return 21; }
	if (mode == "MIPS64")      { return 22; }
	if (mode == "M680X6301")   { return 23; }
	if (mode == "M680X6309")   { return 24; }
	if (mode == "M680X6800")   { return 25; }
	if (mode == "M680X6801")   { return 26; }
	if (mode == "M680X6805")   { return 27; }
	if (mode == "M680X6808")   { return 28; }
	if (mode == "M680X6809")   { return 29; }
	if (mode == "M680X6811")   { return 30; }
	if (mode == "M680XCPU12")  { return 31; }
	if (mode == "M680XHCS08")  { return 32; }
	else                       { return 0;  } // default to LEM
}

// help messages for ezOptionParser
// way easier than having to constantly newline and tab in the function params for ezop.add()
const char* modeHelpStr = R"V0G0N(Target mode [def: LEM].
Available modes:
	LEM         | little-endian mode (default mode)
	ARM         | ARM mode
	16          | 16-bit mode (X86)
	32          | 32-bit mode (X86)
	64          | 64-bit mode (X86, PPC)
	THUMB       | ARM's Thumb mode, including Thumb-2
	MCLASS      | ARM's Cortex-M series
	V8          | ARMv8 A32 encodings for ARM
	V9          | SparcV9 mode (Sparc)
	MICRO       | MicroMips mode (MIPS)
	MIPS3       | Mips III ISA
	MIPS2       | Mips II ISA
	MIPS32R6    | Mips32r6 ISA
	QPX         | Quad Processing eXtensions mode (PPC)
	M68K000     | M68K 68000 mode
	M68K010     | M68K 68010 mode
	M68K020     | M68K 68020 mode
	M68K030     | M68K 68030 mode
	M68K040     | M68K 68040 mode
	M68K060     | M68K 68060 mode
	BEM         | big-endian mode
	MIPS32      | Mips32 ISA (Mips)
	MIPS64      | Mips64 ISA (Mips)
	M680X6301   | M680X Hitachi 6301,6303 mode
	M680X6309   | M680X Hitachi 6309 mode
	M680X6800   | M680X Motorola 6800,6802 mode
	M680X6801   | M680X Motorola 6801,6803 mode
	M680X6805   | M680X Motorola/Freescale 6805 mode
	M680X6808   | M680X Motorola/Freescale/NXP 68HC08 mode
	M680X6809   | M680X Motorola 6809 mode
	M680X6811   | M680X Motorola/Freescale/NXP 68HC11 mode
	M680XCPU12  | M680X Motorola/Freescale/NXP CPU12
	M680XHCS08  | M680X Freescale/NXP HCS08 mode)V0G0N";

const char* archHelpStr = R"V0G0N(Target architecture [def: X86].
Available architectures:
	ARM         | ARM architecture (including Thumb, Thumb-2)
	ARM64       | ARM-64, also called AArch64
	MIPS        | Mips architecture
	X86         | X86 architecture (including x86 & x86-64)
	PPC         | PowerPC architecture
	SPARC       | Sparc architecture
	SYSZ        | SystemZ architecture
	XCORE       | XCore architecture
	M68K        | 68K architecture
	TMS320C64X  | TMS320C64x architecture
	M680X       | 680X architecture
	EVM         | Ethereum architecture
	ALL         | All architectures)V0G0N";