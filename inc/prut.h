#ifndef PRUT_H
#define PRUT_H

#if __cplusplus <= 201103L
  #error This library needs at least a C++11 compliant compiler
#endif

#include <string>
#include <iostream>

#include <disasm.h>

class Prut
{
public:
	Prut(std::string infile_path, int offset);
	Prut(std::string infile_path, int offset, int end);
	~Prut();
	void disassemble();
	void write(std::string outfile_path);

private:
	std::string infile_path_;
	unsigned int offset_;
	unsigned int end_;

	Disasm* disassembly_;
};



















#endif // PRUT_H
