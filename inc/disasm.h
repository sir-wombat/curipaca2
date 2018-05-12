#ifndef DISASM_H
#define DISASM_H

#if __cplusplus <= 201103L
  #error This library needs at least a C++11 compliant compiler
#endif

#include <list>
#include <string>
#include <iostream>
#include <fstream>
#include "op.h"


//typedef std::list<Data> Memlist; // TODO: Replace "Data" with "Op"

class Disasm
{
	public:Disasm(std::string infile_path, int offset);
	public:Disasm(std::string infile_path, int offset, int end);
	public:~Disasm();

	private:std::string infile_path_;
	private:unsigned int offset_;
	private:unsigned int end_;
	private:Memlist program_;
	private:Memlist::iterator pos_;
	private:bool valid_;

	public:int write_disasm();
	public:bool is_valid();

};


#endif //DISASM_H
