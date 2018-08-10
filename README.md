# curipaca2

This is a C++ reimplementation of the original Curipaca decompiler.


## TODOs

- create a class to store functions in
	- at first only the address and information about why it was deemed a function
	- later also information about parameters and return values
- create one or two simple methods to search the machine code for functions
- define a format to save function-start-patterns into files
- write a program to generate pattern files from .ELF files
- create a method which searches for funcitons using the patterns in a file