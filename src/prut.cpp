#include <prut.h>


Prut::Prut(std::string infile_path, int offset, int end)
{
	infile_path_ = infile_path;
	offset_ = offset;
	end_ = end;

	disassembly_ = 0;
}

Prut::Prut(std::string infile_path, int offset):
		Prut(infile_path, offset, 0xffffffff){}

Prut::~Prut()
{
	if(disassembly_ != 0)
	{
		delete disassembly_;
	}

	// Just out of curiosity:
	std::cout << "~Prut() was called!" << std::endl;
}

int Prut::disassemble()
{
	disassembly_ = new Disasm(infile_path_, offset_, end_);
	if (disassembly_->is_valid())
	{
		disassembly_->write_disasm();
		return 0;
	}
	else
	{
		return -1;
	}
}
