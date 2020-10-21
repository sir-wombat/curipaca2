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
#include <vector> // bytearrays for Binfile::read_raw()
#include <unordered_map>

typedef std::list<unsigned int> AddrList;
typedef struct Memranges
{
	unsigned int flash_start;
	unsigned int flash_end;
	unsigned int ram_start;
	unsigned int ram_end;
}Memranges;
typedef std::unordered_map<unsigned int, std::shared_ptr<PsOp>> DataMap;

struct NoFileException : public std::exception {
	// use catch(NoFileExcetpion& e){...} to catch this exception type.
   const char * what () const throw () {
      return "File not found!";
   }
};
struct BadReadSize : public std::exception {
	// use catch(BadReadSize& e){...} to catch this exception type.
   const char * what () const throw () {
      return "Not enough bytes in the file!";
   }
};
struct BadIntSize : public std::exception {
	// use catch(BadIntSize& e){...} to catch this exception type.
   const char * what () const throw () {
      return "Only 4, 2 or 1 Byte integers allowed!";
   }
};

class Binfile
{
public:
	Binfile(std::string infile_path, unsigned int offset, unsigned int end); // open file
	~Binfile(); // close file
	void read_raw(unsigned int address, char* buf, unsigned int size);
	unsigned int read_int(unsigned int address, unsigned int size);
	unsigned int read_int(unsigned int address);
	unsigned int get_end(void);

private:
	std::string infile_path_;
	std::ifstream infile_;
	unsigned int offset_; // address of the very first byte
	unsigned int end_;    // address of the very last byte
	bool little_endian_; // ARM ist mostly LE
	// LE means: least significant byte at lowest address
	// It is implemented as don't change byte order, because
	// most Desktop PCs are LE, too.
};

class Disasm
{
public:
	Disasm(std::string infile_path, unsigned int offset);
	Disasm(std::string infile_path, unsigned int offset, unsigned int end);
	~Disasm();

	void disassemble(void);
	int print_disasm();
	int write_disasm(std::string outfile_path);

private:
	Binfile* binfile_;
	unsigned int offset_;
	unsigned int end_;
	Memlist program_;
	//AddrList vectors_;
	Memranges ranges_;
	DataMap known_data_;

	DataMap find_vectors(void);
	std::shared_ptr<Op> parse_address(unsigned int address, unsigned short length);
	int dis_iter(void);
	void search_data(void);
};


#endif //DISASM_H
