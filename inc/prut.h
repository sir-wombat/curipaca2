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
	public:Prut(std::string infile_path, int offset);
	public:Prut(std::string infile_path, int offset, int end);
	public:~Prut();

	private:std::string infile_path_;
	private:unsigned int offset_;
	private:unsigned int end_;

	private:Disasm* disassembly_;

	public:int disassemble();
};



















#endif // PRUT_H
