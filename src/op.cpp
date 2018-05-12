#include "op.h"
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
std::string Op::print(void)const{return "FAILURE!";}

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

unsigned int PsOp::get_size(void){return size_;}

unsigned int PsOp::get_address(void){return address_;}

unsigned int PsOp::get_value(void){return value_;}

std::string PsOp::print(void)const
{
	std::string pstring;
	std::stringstream ss;
	ss <<  std::hex << std::setfill('0') << "0x" <<
			std::setw(8) << address_<< "\t.data\t" << "0x" <<
			std::setw(8) << value_;
	pstring = ss.str();
	return pstring;
}


