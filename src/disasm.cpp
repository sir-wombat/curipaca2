#if __cplusplus <= 201103L
  #error This library needs at least a C++11 compliant compiler
#endif

#include <disasm.h>



unsigned int buff_value(char* buff, uint8_t size=4, bool big_endian=false)
{
	//precheck:
	if( !(size==4 || size==2 || size==1) )
	{
		std::cout << "Error: called buff_value() with bad value for \"size\"!"
				<< std::endl;
		exit(1);
	}
	if(buff == 0)
	{
		std::cout << "Error: called buff_value() with a nullpointer!"
				<< std::endl;
		exit(1);
	}

	//conversion:
	unsigned int value = 0;
	if(big_endian)
	{
		char buffx[size];
		for(uint8_t i = 0; i<size; i++) buffx[i] = buff[size - (i+1)];
		value = *(unsigned int*)buffx;
	}
	else value = *(unsigned int*)buff;

	return value;
}


Disasm::Disasm(std::string infile_path, int offset, int end)
{
	infile_path_ = infile_path;
	offset_ = offset;
	end_ = end;
	pos_ = program_.begin();
	valid_ = false;

	std::ifstream infile;
	infile.open(infile_path_, std::ios::in | std::ios::binary);
	if(infile.fail() == 1)
	{
		std::cout << "Error: failed to open " << infile_path_ << std::endl;
	}
	else
	{
		infile.seekg(0L, std::ios::end);
		unsigned long count = infile.tellg();
		std::cout << "The input file " << infile_path_ << " is " << count
				<< " bytes long." << std::endl;

		// read the bytes into the list:
		infile.seekg(0L); // go to the start of the file
		char inbuf[4];
		while(!infile.eof())
		{
			unsigned int address = offset_ + infile.tellg();
			infile.read(inbuf ,4);
			unsigned int value = buff_value(inbuf);
			Op* current_word = new PsOp(address, value);
			program_.insert(pos_++, current_word);
		}
		infile.close();
		valid_ = true;
	}
}

// This is called delegation. It's why we need C++11
Disasm::Disasm(std::string infile_path, int offset):
	Disasm::Disasm(infile_path, offset, 0){}

Disasm::~Disasm()
{
	while(!program_.empty())
	{
		delete program_.front();
		program_.pop_front();
	}
	// Just out of curiosity:
	std::cout << "~Disasm() was called!" << std::endl;
}

int Disasm::write_disasm()
{
	pos_ = program_.begin();
	std::cout << "writing disassembly..." << std::endl;
	while(pos_ != program_.end()) std::cout << *pos_++ << std::endl;
	return 0;
}

bool Disasm::is_valid()
{
	return valid_;
}





