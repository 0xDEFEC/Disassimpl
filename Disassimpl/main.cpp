#include <iostream>
#include <io.h>
#include <inttypes.h>
#include "enums.h"
#include "inc/ezop.h"
#include "Python.h"
using namespace ez;

// preproc in/out defs for my OCD
#define D_IN    // for in params  -> DISASSIMPL_IN
#define D_OUT   // for out params -> DISASSIMPL_OUT

ezOptionParser ez_init(int argc, const char* argv[]); void printUsage(D_IN ezOptionParser& opt);
void cs_init(D_IN std::string& arch, D_IN std::string& mode, D_OUT uint16_t& archBuffer, D_OUT int32_t& modeBuffer, D_IN bool debug, D_IN bool infoMode, D_IN std::string filePath, D_IN std::string outfile);
bool importHandler(D_OUT PyObject** moduleBuffer, D_IN const char* modName); // used to import DisassimplHandler.py as a module
bool importSymbols(D_IN PyObject* module, D_IN const char* symbol, D_OUT PyObject** symbolBuffer); // used for importing the necessary functions
bool callSymbol(D_IN PyObject* symbol, D_IN PyObject* pyTupleArgs);

// globals - hold output from cs_init for it to be sent the Py-side
uint16_t arch_buffer;
int32_t mode_buffer;

int main(int argc, const char *argv[]) {
	#ifdef _WIN32
		system("cls");
	#elif __linux__
		system("clear");
	#endif

	ezOptionParser opt = ez_init(argc, argv);
	std::cout << "      [Disassimpl] :: a simple disassembly utility by Mr. D7EAD\n-----------------------------------------------------------------------\n" << std::endl;
	std::string filePath;                 opt.get("-f")->getString(filePath); // check for existence in ez_init()
	std::string arch = "X86";             opt.get("-a")->getString(arch); // has default value X86
	std::string mode = "LEM";             opt.get("-m")->getString(mode); // has default value as LEM
	std::string out  = "None";            opt.get("-o")->getString(out);  // has default value None for Python side

	if (_access(filePath.c_str(), 0) == 0 && !opt.isSet("-i")) { // if file opened successfully
		// begin disassembling - printf used for formatting that std::ostream is not as good at
		if (fopen(filePath.c_str(), "r") == nullptr) { std::cout << "[Disassimpl][MAIN] - Given path is a directory"; exit(CODE_ISDRIECTORY); } // check if dir
		cs_init(arch, mode, arch_buffer, mode_buffer, opt.isSet("-d"), opt.isSet("-i"), filePath, out);
	}
	else if (_access(filePath.c_str(), 0) == 0 && opt.isSet("-i")) {
		// call function on the Py-side that extracts file structure info
		if (fopen(filePath.c_str(), "r") == nullptr) { std::cout << "[Disassimpl][MAIN] - Given path is a directory"; exit(CODE_ISDRIECTORY); } // check if dir
		cs_init(arch, mode, arch_buffer, mode_buffer, opt.isSet("-d"), opt.isSet("-i"), filePath, out);
	}
	else {
		std::cout << "[Disassimpl][MAIN] - Given file is inaccessible";
		exit(CODE_FILEINACCESSIBLE);
	}
	return EXIT_SUCCESS;
}

// used to handle setting target arch, mode, and return format as well as error handling
void cs_init(D_IN std::string& arch, D_IN std::string& mode, D_OUT uint16_t& archBuffer, D_OUT int32_t& modeBuffer, D_IN bool debug, D_IN bool infoMode, D_IN std::string filePath, D_IN std::string outfile) {
	PyObject* module = nullptr; // holds module reference 
	PyObject* parsePE = nullptr; // holds symbol reference to Python function: parsePE
	PyObject* parsePEStruct = nullptr; // holds symbol reference to Python function: parsePEStruct
	PyObject* parseELF = nullptr; // holds symbol reference to Python function: parseELF
	PyObject* parseELFStruct = nullptr; // holds symbol reference to Python function: parseELFStruct
	Py_Initialize();

	// parse -a cli arg and set appropriate value to arch_buffer
	if (!infoMode) { // no need to set nor print if in infoMode
		switch (parseArch(arch)) {
			case 0:         arch_buffer = ARCH_ARM;        arch = "ARM";        std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break;
			case 1:         arch_buffer = ARCH_ARM64;      arch = "ARM64";      std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break;
			case 2:         arch_buffer = ARCH_MIPS;       arch = "MIPS";       std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break;
			case 3:         arch_buffer = ARCH_X86;        arch = "X86";        std::cout << "[Disassimpl][ARCH] - Using default " << arch << " (code " << arch_buffer << ")" << std::endl; break;
			case 4:         arch_buffer = ARCH_PPC;        arch = "PPC";        std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break;
			case 5:         arch_buffer = ARCH_SPARC;      arch = "SPARC";      std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break;
			case 6:         arch_buffer = ARCH_SYSZ;       arch = "SYSZ";       std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break;
			case 7:         arch_buffer = ARCH_XCORE;      arch = "XCORE";      std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break;
//			case 8:         arch_buffer = ARCH_M68K;       arch = "M68K";       std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break; removed
//			case 9:			arch_buffer = ARCH_TMS320C64X; arch = "TMS320C64X"; std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break; removed
//			case 10:        arch_buffer = ARCH_M680X;      arch = "M680X";      std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break; removed
			case 11:        arch_buffer = ARCH_EVM;        arch = "EVM";        std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break;
//			case 0xFFFF:    arch_buffer = ARCH_ALL;        arch = "ALL";        std::cout << "[Disassimpl][ARCH] - Using " << arch << " (code " << arch_buffer << ")" << std::endl; break;
		}
	}

	// parse -m cli arg and set appropriate value to mode_buffer
	if (!infoMode) {
		switch (parseMode(mode)) {
			case 0:         mode_buffer = MODE_LITTLE_ENDIAN;  mode = "LEM";        std::cout << "[Disassimpl][MODE] - Using default " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 1:         mode_buffer = MODE_ARM;			   mode = "ARM";        std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 2:			mode_buffer = MODE_16;             mode = "16-bit";     std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 3:         mode_buffer = MODE_32;             mode = "32-bit";     std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 4:         mode_buffer = MODE_64;             mode = "64-bit";     std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 5:         mode_buffer = MODE_THUMB;          mode = "THUMB";      std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 6:         mode_buffer = MODE_MCLASS;         mode = "MCLASS";     std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 7:         mode_buffer = MODE_V8;             mode = "V8";         std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 8:         mode_buffer = MODE_V9;             mode = "V9";         std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 9:         mode_buffer = MODE_MICRO;          mode = "MICRO";      std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 10:        mode_buffer = MODE_MIPS3;          mode = "MIPS3";      std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 11:        mode_buffer = MODE_MIPS2;          mode = "MIPS2";      std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 12:        mode_buffer = MODE_MIPS32R6;       mode = "MIPS32R6";   std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 13:        mode_buffer = MODE_QPX;            mode = "QPX";        std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
//			case 14:        mode_buffer = MODE_M68K_000;       mode = "M68K000";    std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 15:        mode_buffer = MODE_M68K_010;       mode = "M68K010";    std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 16:        mode_buffer = MODE_M68K_020;       mode = "M68K020";    std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 17:        mode_buffer = MODE_M68K_030;       mode = "M68K030";    std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 18:        mode_buffer = MODE_M68K_040;       mode = "M68K040";    std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 19:        mode_buffer = MODE_M68K_060;       mode = "M68K060";    std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
			case 20:        mode_buffer = MODE_BIG_ENDIAN;     mode = "BEM";        std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 21:        mode_buffer = MODE_MIPS32;         mode = "MIPS32";     std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
			case 22:        mode_buffer = MODE_MIPS64;         mode = "MIPS64";     std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break;
//			case 23:        mode_buffer = MODE_M680X_6301;     mode = "M680X6301";  std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 24:		mode_buffer = MODE_M680X_6309;     mode = "M680X6309";  std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 25:		mode_buffer = MODE_M680X_6800;     mode = "M680X6800";  std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 26:		mode_buffer = MODE_M680X_6801;     mode = "M680X6801";  std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 27:		mode_buffer = MODE_M680X_6805;     mode = "M680X6805";  std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 28:		mode_buffer = MODE_M680X_6808;     mode = "M680X6808";  std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 29:		mode_buffer = MODE_M680X_6809;     mode = "M680X6809";  std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 30:		mode_buffer = MODE_M680X_6811;     mode = "M680X6811";  std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 31:		mode_buffer = MODE_M680X_CPU12;    mode = "M680XCPU12"; std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
//			case 32:		mode_buffer = MODE_M680X_HCS08;    mode = "M680XHCS08"; std::cout << "[Disassimpl][MODE] - Using " << mode << " (code " << mode_buffer << ")" << std::endl; break; removed
		}
	}

	// begin Python symbol and module imports
	if (!importHandler(&module, "DisassimplHandler")) {
		Py_Finalize(); // cleanup
		exit(CODE_PY_MODIMPORTFAILURE);
	} if (debug) { std::cout << "[Disassimpl][INFO] - DEBUG[module imported, saved at 0x" << module << "] (module: DisassimplHandler)" << std::endl; }
	if (!infoMode) { // only import disassembly function when not in infoMode - will import when -i is not set
		if (!importSymbols(module, "parsePE", &parsePE)) {
			Py_Finalize(); // cleanup
			exit(CODE_PY_SYMIMPORTFAILURE);
		} if (debug) { std::cout << "[Disassimpl][INFO] - DEBUG[symbol imported, saved at 0x" << parsePE << "] (symbol: parsePE)" << std::endl; }
	}
	if (infoMode) { // only import infoMode function when in infoMode -  will import when -i is set
		if (!importSymbols(module, "parsePEStruct", &parsePEStruct)) {
			Py_Finalize(); // cleanup
			exit(CODE_PY_SYMIMPORTFAILURE);
		} if (debug) { std::cout << "[Disassimpl][INFO] - DEBUG[symbol imported, saved at 0x" << parsePEStruct << "] (symbol: parsePEStruct)" << std::endl; }
	}

	// begin Python callbacks
	if (infoMode) {
		if (outfile == "None") { // if outfile not provided
			std::cout << "[Disassimpl][MAIN] - Beginning file info extraction..." << std::endl;
			if (!callSymbol(parsePEStruct, PyTuple_Pack(1, PyBytes_FromString(filePath.c_str())))) {
				Py_Finalize(); // cleanup
				exit(CODE_PY_CALLBACKFAILURE);
			}
		}
		else { // if outfile provided
			std::cout << "[Disassimpl][MAIN] - Beginning file info extraction..." << std::endl;
			if (!callSymbol(parsePEStruct, PyTuple_Pack(2, PyBytes_FromString(filePath.c_str()), PyBytes_FromString(outfile.c_str())))) {
				Py_Finalize(); // cleanup
				exit(CODE_PY_CALLBACKFAILURE);
			}
		}
	}
	else if (!infoMode) {
		if (outfile == "None") {
			if (!callSymbol(parsePE, PyTuple_Pack(3, PyBytes_FromString(filePath.c_str()), PyLong_FromLong(arch_buffer), PyLong_FromLong(mode_buffer)))) {
				Py_Finalize(); // cleanup
				exit(CODE_PY_CALLBACKFAILURE);
			}
		}
		else {
			if (!callSymbol(parsePE, PyTuple_Pack(4, PyBytes_FromString(filePath.c_str()), PyLong_FromLong(arch_buffer), PyLong_FromLong(mode_buffer), PyBytes_FromString(outfile.c_str())))) {
				Py_Finalize(); // cleanup
				exit(CODE_PY_CALLBACKFAILURE);
			}
		}
	}

	Py_Finalize(); // finally... cleanup after all
}

// function used to initialize command line args
// performs check to see if an input file is detected - every other check is done in main()
ezOptionParser ez_init(int argc, const char* argv[]) {
	ezOptionParser ezop;
	ezop.overview = "[Disassimpl] :: a somewhat simple disassembly utility by D7EAD";
	ezop.syntax = "(./)Disassimpl(.exe) [OPTIONS...] -f [FILEPATH]";
	ezop.example = "[WIN32]\nDisassimpl.exe -f C:\\somebinary.exe -m 64 -a X86\nDisassimpl.exe -f C:\\somebinary.exe\n\n[LINUX]\n./Disassimpl -f /home/user/somebinary -m 64 -a X86\n./Disassimpl -f /home/user/somebinary";
	ezop.add(
		"",  // Default value
		0,   // Required?
		0,   // Number of args expected
		0,   // Delimiter if expecting multiple args
		"Display usage instructions.", // Help description
		"-h" // Flag token(s)...
	);
	ezop.add("", 0, 1, 0, "Full path to target file to disassemble.", "-f");
	ezop.add("LEM", 0, 1, 0, modeHelpStr, "-m"); // archHelpStr defined in enums.h
	ezop.add("X86", 0, 1, 0, archHelpStr, "-a");
	ezop.add("false", 0, 0, 0, "Output file information rather than disassemble [def: off].", "-i");
	ezop.add("false", 0, 0, 0, "Enable debug mode - shows extra steps [def: off].", "-d");
	ezop.add("None", 0, 1, 0, "Send Disassimpl output to specified file [def: none].", "-o");
	ezop.parse(argc, argv);
	if (ezop.isSet("-h")) {
		printUsage(ezop);
		exit(CODE_HELPREQUEST);
	}
	else if (!ezop.isSet("-f")) {
		printUsage(ezop);
		std::cout << "\n\n[Disassimpl][MAIN] No input file found!";
		exit(CODE_FILENOTFOUND);
	}
	return ezop;
}

// helper function to print help message
void printUsage(D_IN ezOptionParser& opt) {
	std::string usage;
	opt.getUsage(usage);
	std::cout << usage;
}

// Python functions all below - PyErr_Print() fills the Disassimpl error dialogue following the hyphen if an error occurs
bool importHandler(D_OUT PyObject** moduleBuffer, D_IN const char* modName) {
	*moduleBuffer = PyImport_ImportModule(modName);
	if (!moduleBuffer) {
		printf("[Disassimpl][MAIN] - "); PyErr_Print();
		return false;
	}
	else {
		return true;
	}
} bool importSymbols(D_IN PyObject* module, D_IN const char* symbol, D_OUT PyObject** symbolBuffer) {
	*symbolBuffer = PyObject_GetAttrString(module, symbol);
	if (!symbolBuffer) {
		printf("[Disassimpl][MAIN] - "); PyErr_Print();
		return false;
	}
	else {
		return true;
	}
} bool callSymbol(D_IN PyObject* symbol, D_IN PyObject* pyTupleArgs) {
	if (!PyObject_CallObject(symbol, pyTupleArgs)) {
		printf("[Disassimpl][MAIN] - "); PyErr_Print();
		return false;
	}
	else {
		return true;
	}
}
