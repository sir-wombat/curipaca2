#if __cplusplus <= 201103L
  #error This library needs at least a C++11 compliant compiler
#endif

#include <disasm.h>



unsigned int buff_value(unsigned char* buff, uint8_t size=4, bool big_endian=false)
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
		unsigned char inbuf[4];
		while(!infile.eof())
		{
			// TODO:
			// Mechanism to always feed the next four bytes to RlOp()
			// and not skip any (if the last instruction was only 2 bytes long).
			// TODO:
			// Mechanism to turn known data bytes directly into PsOp Objects.
			unsigned int address = offset_ + infile.tellg();
			infile.read((char*)inbuf ,4);
			unsigned int value = buff_value(inbuf);

			//Op* current_word = new RlOp(address, inbuf);
			std::shared_ptr<Op> current_word = std::make_shared<RlOp>(address, inbuf);
			//std::cout << "in Disasm()" << current_word << std::endl;

			if(current_word->get_size() == 0)
			{
				// delete current_word; not needed anymore with shared_ptr
				//current_word = new PsOp(address, value);
				current_word = std::make_shared<PsOp>(address, value);
			}
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
		// delete program_.front(); not needed anymore with shared_ptr
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





