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
unsigned int Op::get_address(void){return address_;}
unsigned int Op::get_size(void){return size_;}
std::string Op::print(void)const
{
	std::cout << "Error: called Op::print()" << std::endl;
	exit(-1);
	return ""; // never happens
}


RlOp::RlOp(unsigned long int address,
		const unsigned char* bytes)
{
	size_t size = 4;
	address_ = address;
	size_ = size;
	csop_ = 0; //TODO replace!!!
	// TODO Error handling:
	// What happens if size==0
	// What happens if if capstone doesn't give back a valid instruction?
	// Use 'exit -1;'
	csh handle; // Capstone Handler
	if( cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) )
	{
		std::cout
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
}

std::string RlOp::print(void)const
{
	std::string pstring;
	std::stringstream ss;
	ss <<  std::hex << std::setfill('0') << "0x"
	<< std::setw(8) << address_<< "\t"
	<< csop_->mnemonic << "\t" << csop_->op_str;
	pstring = ss.str();
	return pstring;
}


PsOp::PsOp(unsigned int address, unsigned int value, unsigned int size, std::string comment)
{
	address_ = address;
	value_ = value;
	size_ = size;
	comment_ = comment;
	//std::cout << "PsOp() was called!";
}

PsOp::PsOp(unsigned int address, unsigned int value):
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
	ss <<  std::hex << std::setfill('0') << "0x"
	<< std::setw(8) << address_<< "\t.data\t" << "0x"
	<< std::setw(8) << value_;
	pstring = ss.str();
	return pstring;
}


