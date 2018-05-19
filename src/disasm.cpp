#if __cplusplus <= 201103L
  #error This library needs at least a C++11 compliant compiler
#endif

#include <disasm.h>



unsigned int buff_value(unsigned char* buff, uint8_t size=4, bool big_endian=false)
{
	//precheck:
	if( !(size==4 || size==2 || size==1) )
	{
		std::cerr << "ERROR: called buff_value() with bad value for \"size\"!"
				<< std::endl;
		exit(-1);
	}
	if(buff == 0)
	{
		std::cerr << "ERROR: called buff_value() with a nullpointer!"
				<< std::endl;
		exit(-1);
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


Disasm::Disasm(std::string infile_path, unsigned long offset, unsigned long end)
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
		//File is open. Get ready for reading it:
		unsigned long read_addr = offset_;
		unsigned char inbuf[4]; // read buffer

		infile.seekg(0L, std::ios::end);
		unsigned long fsize = infile.tellg();
		std::cout << "The input file " << infile_path_ << " is " << fsize
				<< " bytes long." << std::endl;
		if(end_ - offset_ != fsize)
		{
			std::cout << "WARNING: File is " << fsize
			<< " bytes long but the address range is "
			<< end-offset << " bytes long! ";
			end_ = fsize + offset_;
			std::cout << "Adjusted address range accordingly." << std::endl;
		}

		// read the bytes into the list:
		infile.seekg(read_addr - offset_); // go to the start of the file

		while( read_addr <= end_ - 4 )
		{
			// TODO:
			// Mechanism to turn known data bytes directly into PsOp Objects.
			// TODO:
			// Separate disassembly from disasm constructor.
			// TODO:
			// cover edge case with (read_addr == end_ - 2)
			// TODO:
			// Turn Memlist / program_ into a separate class?
			infile.seekg(read_addr - offset_);
			infile.read((char*)inbuf ,4);

			//std::cout << "read_addr - offset_ = " << read_addr - offset_ << std::endl;

			std::shared_ptr<Op> current_word = std::make_shared<RlOp>(read_addr, inbuf, 4);
			//std::cout << "in Disasm()" << current_word << std::endl;
			if(current_word->get_size() == 0)
			{
				unsigned int value = buff_value(inbuf);
				current_word = std::make_shared<PsOp>(read_addr, value);
				read_addr += 4;
			}
			else if(current_word->get_size() == 2) read_addr += 2;
			else if(current_word->get_size() == 4) read_addr += 4;
			else
			{
				std::cerr << "ERROR: current_word has a bad size!" << std::endl;
			}
			pos_ = program_.end();
			program_.insert(pos_, current_word);
		}

		// program_.sort(Op::comp_addr_ptr);
		// not needed when everything is appended at the back

		infile.close();
		valid_ = true;
	}
}

// This is called delegation. It's why we need C++11
Disasm::Disasm(std::string infile_path, unsigned long offset):
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





