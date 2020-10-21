# curipaca2

This is a C++ reimplementation of the original Curipaca decompiler.

## Notes
Disassemble an ARM ELF file:
```
apt install binutils-arm-none-eabi
arm-none-eabi-objdump demsys-O3.elf -d
```

## TODOs
- ~~create some way to store known data addresses~~
	- this is needed for the disassembly iterations
	- find out in which format to store them (Python Dictionary Equivalent?)
	- _Solution:_ std::unordered_map
- Modify op.h/op.cpp so that a RlOp gets capabillities check wether it contains
	hints about data addresses.
- detect branch tables correctly
	- example: 0x0800454a in demsys-O3
	- Make it work
- create a class represent functions
	- at first only the address and information about why it was deemed a function
	- later also information about parameters and return values
- create something to store function-objects in
- create one or two simple methods to search the machine code for functions
- define a format to save function-start-patterns into files
- write a program to generate pattern files from .ELF files
- create a method which searches for funcitons using the patterns in a file
- Error handling for Disasm::write_disasm


## Algorithm Ideas

### Branch Target Sanity
A branch target cannot be a data area, so either the branch command is bad (unlikely, if it points to the very limited address range of flash / ram memory) or the target address has wrongfully been marked as data.