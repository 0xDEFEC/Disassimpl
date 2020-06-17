# Module: DisassimplHandler.py
#   @modinfo
#       This is the module that contains the functions that are called from the C++ side of things.
#       These functions are responsible for disassembly on a supplied file and determining the filetype - PE, ELF.
#           - They also perform all Python-side error checks and transparently print errors when necessary on the C++ side.
#       Simply, these functions will disassemble the C++ supplied file, given the C++ supplied mode and arch, and print it seamlessly.
#   @extra
#       I offhanded the disassembly process to Python because I could not, for the life of me, figure out why the Capstone C API hates me so much.
#       Anyway, I sorta like this method of disassembly better anyway--I miss using Python, even though this does require more dependencies.
#       I mean, if you're trying to use a disassembler, you probably don't mind installing Python3 and the packages anyway, right? Yeah.

from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.elf.constants import E_FLAGS, E_FLAGS_MASKS
from elftools.common.py3compat import byte2int
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import NoteSection, SymbolTableSection
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric
    )
import pefile
import io

def parsePE(file_path, arch, mode, out="None"):
    try:
        print("[Disassimpl][MAIN] - Beginning disassembly...")
        pe = pefile.PE(file_path)
        eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        code_section = pe.get_section_by_rva(eop)
        code_dump = code_section.get_data()
        code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
        md = Cs(arch, mode)
        if (out == "None"):
            print()
            for i in md.disasm(code_dump, code_addr):
                print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        else:
            try:
                with open(str(out, "utf-8"), "w") as outfile:
                    for i in md.disasm(code_dump, code_addr):
                        outfile.write("0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str))
                    outfile.close()
                    print("[Disassimpl][MAIN] - Results saved to file")
            except PermissionError as pErr:
                print("[Disassimpl][MAIN] - Permission denied on file")
    except pefile.PEFormatError as pe_err:
        print("[Disassimpl][MAIN] - Supplied file is not of type PE--trying ELF")
        parseELF(file_path, arch, mode, out)
    except KeyboardInterrupt as k:
        print("Exiting...")
    except Exception as e:
        print("[Disassimpl][MAIN] - Error {}".format(e))

# function used to return the structure contents and general information of a PE file
# i.e. bit size, SECTIONS, HEADERS, etc.
def parsePEStruct(file_path, out="None"):
    try:
        pe = pefile.PE(file_path)
        if (out == "None"):
            print("\n----------GENERAL----------")
            if (hex(pe.FILE_HEADER.Machine) == '0x14c'):
                print("\n[BITSIZE_INFORMATION]\n{}\t\t 32-bit Binary\n".format(hex(pe.FILE_HEADER.Machine)))
            else:
                print("\n[BITSIZE_INFORMATION]\n{}\t\t 64-bit Binary\n".format(hex(pe.FILE_HEADER.Machine)))
            pe.print_info()
        else:
            try:
                with open(str(out, "utf-8"), "w") as outfile:
                    outfile.write("----------GENERAL----------\n\n")
                    if (hex(pe.FILE_HEADER.Machine) == '0x14c'):
                        outfile.write("[BITSIZE_INFORMATION]\n{}\t\t 32-bit Binary\n\n".format(hex(pe.FILE_HEADER.Machine)))
                    else:
                        outfile.write("[BITSIZE_INFORMATION]\n{}\t\t 64-bit Binary\n\n".format(hex(pe.FILE_HEADER.Machine)))
                    fi = io.StringIO()
                    print(pe.dump_info(), file=fi)
                    outfile.write(fi.getvalue())
                    outfile.close()
                    fi.close()
                    print("[Disassimpl][MAIN] - Results saved to file")
            except PermissionError as pErr:
                print("[Disassimpl][MAIN] - Permission denied on file")                        
    except pefile.PEFormatError as pe_err:
        print("[Disassimpl][MAIN] - Supplied file is not of type PE--trying ELF")
        parseELFStruct(file_path, out)
    except KeyboardInterrupt as k:
        print("Exiting...")
    except Exception as e:
        print("[Disassimpl][MAIN] - Error {}".format(e))

def parseELF(file_path, arch, mode, out="None"):
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            code = elf.get_section_by_name('.text')
            ops = code.data()
            addr = code['sh_addr']
            md = Cs(arch, mode)
            if (out == "None"):
                print() # pretty line break
                for i in md.disasm(ops, addr):        
                    print("{0: <16}{1: <8}{2}".format(_format_hex(i.address, elf) + ":", i.mnemonic, i.op_str))
            else:
                try:
                    with open(str(out, "utf-8"), "w") as outfile:
                        for i in md.disasm(ops, addr):        
                            outfile.write("{0: <16}{1: <8}{2}\n".format(_format_hex(i.address, elf) + ":", i.mnemonic, i.op_str))            	
                        outfile.close()
                except PermissionError as pErr:
                    print("[Disassimpl][MAIN] - Permission denied on file")
            f.close()

    except ELFError as ELFErr:
        print("[Disassimpl][MAIN] - File is not of type ELF or PE")
    except KeyboardInterrupt as k:
    	print("Exiting...")
    except Exception as e:
        print("[Disassimpl][MAIN] - Error {}".format(e))

def parseELFStruct(file_path, out="None"):
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            if (display_elf_fh(elf, out) == False):
                return
            if (display_elf_sh(elf, out) == False):
                return
            # display_elf_rl(elf) might add more
            f.close()
    except ELFError as ELFErr:
        print("[Disassimpl][MAIN] - File is not of type ELF or PE")
    except KeyboardInterrupt as k:
    	print("Exiting...")
    except Exception as e:
    	print("[Disassimpl][MAIN] - Error {}".format(e))

def display_elf_fh(elf, out):
    header = elf.header
    e_ident = header['e_ident']
    if (out == "None"):
        print("\n----------ELF_HEADER----------")
        print("Magic:                             {}".format(' '.join('%2.2x' % byte2int(b) for b in elf.e_ident_raw)))
        print("Class:                             {}".format(describe_ei_class(e_ident['EI_CLASS'])))
        print("Data:                              {}".format(describe_ei_data(e_ident['EI_DATA'])))
        print("Version:                           {}".format(describe_ei_version(e_ident['EI_VERSION'])))
        print("OS | ABI:                          {}".format(describe_ei_osabi(e_ident['EI_OSABI'])))
        print("ABI version:                       {}".format(e_ident['EI_ABIVERSION']))
        print("Type:                              {}".format(describe_e_type(header['e_type'])))
        print("Machine:                           {}".format(describe_e_machine(header['e_machine'])))
        print("Version:                           {}".format(describe_e_version_numeric(header['e_version'])))
        print("Entry Point:                       {}".format(_format_hex(header['e_entry'], elf)))
        print("Program Header Start:              {} (bytes in)".format(header['e_phoff']))
        print("Section Header Start:              {} (bytes in)".format(header['e_shoff']))
        print("Flags:                             {}{}".format(_format_hex(header['e_flags'], elf), decode_flags(header['e_flags'], elf)))
        print("Header Size:                       {}".format(header['e_ehsize']))
        print("Program Headers Size:              {}".format(header['e_phentsize']))
        print("Program Header Count:              {}".format(header['e_phnum']))
        print("Section Headers Size:              {}".format(header['e_shentsize']))
        print("Section Header Count:              {}".format(header['e_shnum']))
        print("Section Header String Table Index: {}".format(header['e_shstrndx']))
    else:
        try:
            with open(str(out, "utf-8"), "w") as outfile:
                outfile.write("----------ELF_HEADER----------\n")
                outfile.write("Magic:                             {}\n".format(' '.join('%2.2x' % byte2int(b) for b in elf.e_ident_raw)))
                outfile.write("Class:                             {}\n".format(describe_ei_class(e_ident['EI_CLASS'])))
                outfile.write("Data:                              {}\n".format(describe_ei_data(e_ident['EI_DATA'])))
                outfile.write("Version:                           {}\n".format(describe_ei_version(e_ident['EI_VERSION'])))
                outfile.write("OS | ABI:                          {}\n".format(describe_ei_osabi(e_ident['EI_OSABI'])))
                outfile.write("ABI version:                       {}\n".format(e_ident['EI_ABIVERSION']))
                outfile.write("Type:                              {}\n".format(describe_e_type(header['e_type'])))
                outfile.write("Machine:                           {}\n".format(describe_e_machine(header['e_machine'])))
                outfile.write("Version:                           {}\n".format(describe_e_version_numeric(header['e_version'])))
                outfile.write("Entry Point:                       {}\n".format(_format_hex(header['e_entry'], elf)))
                outfile.write("Program Header Start:              {} (bytes in)\n".format(header['e_phoff']))
                outfile.write("Section Header Start:              {} (bytes in)\n".format(header['e_shoff']))
                outfile.write("Flags:                             {}{}\n".format(_format_hex(header['e_flags'], elf), decode_flags(header['e_flags'], elf)))
                outfile.write("Header Size:                       {}\n".format(header['e_ehsize']))
                outfile.write("Program Headers Size:              {}\n".format(header['e_phentsize']))
                outfile.write("Program Header Count:              {}\n".format(header['e_phnum']))
                outfile.write("Section Headers Size:              {}\n".format(header['e_shentsize']))
                outfile.write("Section Header Count:              {}\n".format(header['e_shnum']))
                outfile.write("Section Header String Table Index: {}\n".format(header['e_shstrndx']))
                outfile.close()
        except PermissionError as pErr:
        	print("[Disassimpl][MAIN] - Permission denied on file")
        	return False
        except Exception as e:
            print("[Disassimpl][MAIN] - Error {}".format(e))
            return False

# Lazy section info.
	# Address is spaced 20 times from Offset due to
	# IA-64 using all 64-bits of its address space
	# like a crazy person.
def display_elf_sh(elf, out):
    if (out == "None"): # no outfile provided
        print("----------SECTIONS----------\n")
        print("{0: <20}{1: <14}{2: <22}{3: <20}{4}".format("Address", "Offset", "Name", "Type", "Size"))
        for sect in elf.iter_sections():
            print("{0: <20}{1: <14}{2: <22}{3: <20}{4}".format(_format_hex(sect['sh_addr'], elf), _format_hex(sect['sh_offset'], elf), sect.name, sect['sh_type'], sect['sh_size']))
    else:
        try:
            with open(str(out, "utf-8"), "a") as outfile:
                outfile.write("\n----------SECTIONS----------\n")
                outfile.write("{0: <20}{1: <14}{2: <22}{3: <20}{4}\n".format("Address", "Offset", "Name", "Type", "Size"))
                for sect in elf.iter_sections():
                    outfile.write("{0: <20}{1: <14}{2: <22}{3: <20}{4}\n".format(_format_hex(sect['sh_addr'], elf), _format_hex(sect['sh_offset'], elf), sect.name, sect['sh_type'], sect['sh_size']))
                outfile.close()
                print("[Disassimpl][MAIN] - Results saved to file")
        except PermissionError as pErr:
        	print("[Disassimpl][MAIN] - Permission denied on file")
        	return False
        except Exception as e:
            print("[Disassimpl][MAIN] - Error {}".format(e))
            return False

#def display_elf_rl(elf):
#    print("\n----------RELOCATIONS----------")
#    print("\t{0: <14}{1}".format("Address", "Name"))
#    for sect in elf.iter_sections():
#        if isinstance(sect, RelocationSection):
#            print("{}:".format(sect.name))
#            symbol_table = elf.get_section(sect['sh_link'])
#            for relocation in sect.iter_relocations():
#                symbol = symbol_table.get_symbol(relocation['r_info_sym'])
#                addr = hex(relocation['r_offset'])
#                print("\t{0: <14}{1}".format(addr, symbol.name))

# helpers for ELF - from readelf
def decode_flags(flags, elf):
    description = ""
    if elf['e_machine'] == "EM_ARM":
        eabi = flags & E_FLAGS.EF_ARM_EABIMASK
        flags &= ~E_FLAGS.EF_ARM_EABIMASK
        if flags & E_FLAGS.EF_ARM_RELEXEC:
            description += ', relocatable executable'
            flags &= ~E_FLAGS.EF_ARM_RELEXEC
        if eabi == E_FLAGS.EF_ARM_EABI_VER5:
            EF_ARM_KNOWN_FLAGS = E_FLAGS.EF_ARM_ABI_FLOAT_SOFT|E_FLAGS.EF_ARM_ABI_FLOAT_HARD|E_FLAGS.EF_ARM_LE8|E_FLAGS.EF_ARM_BE8
            description += ', Version5 EABI'
            if flags & E_FLAGS.EF_ARM_ABI_FLOAT_SOFT:
                description += ", soft-float ABI"
            elif flags & E_FLAGS.EF_ARM_ABI_FLOAT_HARD:
                description += ", hard-float ABI"
            if flags & E_FLAGS.EF_ARM_BE8:
                description += ", BE8"
            elif flags & E_FLAGS.EF_ARM_LE8:
                description += ", LE8"
            if flags & ~EF_ARM_KNOWN_FLAGS:
                description += ', <unknown>'
        else:
            description += ', <unrecognized EABI>'
    elif elf['e_machine'] == "EM_MIPS":
        if flags & E_FLAGS.EF_MIPS_NOREORDER:
            description += ", noreorder"
        if flags & E_FLAGS.EF_MIPS_PIC:
            description += ", pic"
        if flags & E_FLAGS.EF_MIPS_CPIC:
            description += ", cpic"
        if (flags & E_FLAGS.EF_MIPS_ABI2):
            description += ", abi2"
        if (flags & E_FLAGS.EF_MIPS_32BITMODE):
            description += ", 32bitmode"
        if (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O32):
            description += ", o32"
        elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O64):
            description += ", o64"
        elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI32):
            description += ", eabi32"
        elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI64):
            description += ", eabi64"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
            description += ", mips1"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_2:
            description += ", mips2"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_3:
            description += ", mips3"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_4:
            description += ", mips4"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_5:
            description += ", mips5"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32R2:
            description += ", mips32r2"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64R2:
            description += ", mips64r2"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32:
            description += ", mips32"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64:
            description += ", mips64"
    return description

def _format_hex(addr, elf, fieldsize=None, fullhex=False, lead0x=True, alternate=False):
    if alternate:
        if addr == 0:
            lead0x = False
        else:
            lead0x = True
            fieldsize -= 2
    s = '0x' if lead0x else ''
    if fullhex:
        fieldsize = 8 if elf.elfclass == 32 else 16
    if fieldsize is None:
        field = '%x'
    else:
        field = '%' + '0%sx' % fieldsize
    return s + field % addr
