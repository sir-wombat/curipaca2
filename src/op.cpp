#include "op.h"
#include <iostream> // for Error Messages
#include <sstream>
#include <iomanip> // für std::setw


Op::Op(void)
{
	size_ = 0;
	address_ = 0;
}
Op::~Op(void){}
unsigned int Op::get_address(void) const {return address_;}
unsigned int Op::get_size(void) const {return size_;}
bool Op::lower_address(const Op& comp_op) const {return address_ < comp_op.get_address();}
std::string Op::print(void)const
{
	std::cout << "Error: called Op::print()" << std::endl;
	exit(-1);
	return ""; // never happens
}

bool Op::comp_addr(const Op& A, const Op& B)
{
	return A.get_address() < B.get_address();
}
bool Op::comp_addr_ptr(std::shared_ptr<Op> A, std::shared_ptr<Op> B)
{
	return comp_addr(*A, *B);
}

RlOp::RlOp(unsigned long int address,
		const unsigned char* bytes, size_t size)
{
	//std::cout << "RlOp() start...";
	if(size == 0)
	{
		std::cerr << "ERROR: Called RlOp() with size = 0!" << std::endl;
		exit(-1);
	}
	address_ = address;
	size_ = size;
	csop_ = 0; //TODO replace!!!
	// TODO Error handling:
	// Q: What happens if size==0?
	// A: something bad happened. Use exit(-1);
	// Q: What happens if if capstone doesn't give back a valid instruction?
	// A: RlOp gets size_ = 0. Layers above
	//    decide what to do with that.
	csh handle; // Capstone Handler
	if( cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) )
	{
		std::cerr
		<< "ERROR: Failed to initialize the Capstone Engine!"
		<< std::endl;
		exit(-1);
	}
	size_t count=0;
	count = cs_disasm(handle, bytes, size, address, count, &csop_);
	switch(count)
	{
		case 0:
			size_ = 0;
			break;
		case 1:
			size_ = csop_->size;
			break;
		case 2:
			size_ = csop_->size;
			break;
		default:
			std::cerr << "ERROR: count=" << count << " in RlOp()." << std::endl;
			exit(-1);
	}
	if(count and 0)
	{
		size_t j;
		for (j = 0; j < count; j++)
		{
			printf("0x%" PRIx64 ":\t%s\t\t%s\n", csop_[j].address,
					csop_[j].mnemonic, csop_[j].op_str);
		}
		cs_free(csop_, count);
	}
	cs_close(&handle);
	//std::cout << "end!" << std::endl;
}

RlOp::~RlOp(void)
{
	//std::cout << "~RlOp() was called!";
}


std::string RlOp::print(void)const
{
	//std::cout << "in RlOp::print csop_ = " << "0x" << std::hex
	//<< std::setfill('0') << std::setw(8) << csop_ << std::endl;
	std::string pstring;
	std::stringstream ss;
	ss << "0x" << std::hex
	<< std::setfill('0') << std::setw(8) << address_ << "  "
	<< std::setfill(' ') << std::setw(14) << std::left << csop_->mnemonic
	<< csop_->op_str;
	pstring = ss.str();
	return pstring;
}


PsOp::PsOp(unsigned int address, int value, unsigned int size, std::string comment)
{
	//std::cout << "PsOP() start...";
	address_ = address;
	value_ = value;
	size_ = size;
	comment_ = comment;
	//std::cout << "end!" << std::endl;
}

PsOp::PsOp(unsigned int address, int value):
	PsOp::PsOp(address, value, 4, ".data"){}

PsOp::PsOp():
	PsOp::PsOp(0, 0){}

PsOp::~PsOp(void)
{
	//std::cout << "~PsOp() was called!";
}


unsigned int PsOp::get_value(void){return value_;}

std::string PsOp::print(void)const
{
	std::string pstring;
	std::stringstream ss;
	ss << "0x" << std::hex << std::setfill('0')
	<< std::setw(8) << address_<< "  "
	<< std::setfill(' ') << std::setw(14) << std::left << comment_
	<< std::right << "0x" << std::setfill('0') << std::setw(8) << value_;
	pstring = ss.str();
	return pstring;
}


