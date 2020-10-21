#include "function.h"
#include <iostream>
#include <sstream>
#include <iomanip>

Function::Function(unsigned int address, std::string reason)
{
	std::cout << "Function() was called!" << std::endl;
	address_ = address;
	reason_ = reason;
}

Function::Function(unsigned int address):
		Function(address, ""){}

Function::~Function(void)
{
	std::cout << "~Function() was called!" << std::endl;
}


unsigned int Function::get_address(void)
{
	return address_;
}

std::string Function::get_reason(void)
{
	return reason_;
}

std::string Function::str(void)
{
	std::string str;
	std::stringstream ss;
	ss << "Function 0x" << std::hex << std::setfill('0')
	<< std::setw(8) << address_<< " "  << reason_;
	str = ss.str();
	return str;
}
