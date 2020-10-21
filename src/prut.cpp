#include <prut.h>


Prut::Prut(std::string infile_path, int offset, int end)
{
	infile_path_ = infile_path;
	offset_ = offset;
	end_ = end;

	disassembly_ = 0;
	//std::cout << "Prut() was called!" << std::endl;
}

Prut::Prut(std::string infile_path, int offset):
		Prut(infile_path, offset, 0x09000000){}

Prut::~Prut()
{
	if(disassembly_ != 0) delete disassembly_;
	//std::cout << "~Prut() was called!" << std::endl;
}

void Prut::disassemble()
{
	disassembly_ = new Disasm(infile_path_, offset_, end_);
	disassembly_->disassemble();
	//disassembly_->print_disasm();
	return;
}

void Prut::write(std::string outfile_path)
{
	disassembly_->write_disasm(outfile_path);
	return;
}
