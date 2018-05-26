#if __cplusplus <= 201103L
  #error This library needs at least a C++11 compliant compiler
#endif

#include <disasm.h>
#include <algorithm> // for std::find



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


Binfile::Binfile(std::string infile_path, unsigned int offset, unsigned int end)
{
	infile_path_ = infile_path;
	infile_.open(infile_path_, std::ios::in | std::ios::binary);
	if(infile_.fail() == 1)
	{
		std::cerr << "ERROR: failed to open " << infile_path_ << std::endl;
		throw NoFileException(); // instead of exit(-1);
	}
	offset_ = offset;
	end_ = end;
	little_endian_ = true; // unless specified otherwise

	infile_.seekg(0L, std::ios::end);
	unsigned int fsize = infile_.tellg();
	std::cout << "The input file " << infile_path_ << " is " << fsize
			<< " bytes int." << std::endl;
	if(end_ - offset_ != fsize - 1)
	{
		// 101% sure that there is no off-by-one-error around here...
		std::cout << "WARNING: File is " << fsize
		<< " bytes long but the address range is "
		<< end_-offset_ + 1 << " bytes long! ";
		end_ = fsize + offset_ -1;
		std::cout << "Adjusted address range accordingly." << std::endl;
		// no exception because this can be handled
	}
}

Binfile::~Binfile()
{
	infile_.close();
}

void Binfile::read_raw(unsigned int address, char* buf, unsigned int size)
{
	infile_.seekg(address - offset_);
	if(address + size - 1 > end_) throw BadReadSize();
	infile_.read(buf, size);
	return;
}

int Binfile::read_int(unsigned int address, unsigned int size)
{
	int value = 0;
	if(not (size == 4 || size == 2 || size == 1)) throw BadIntSize();
	else
	{
		char* buf = new char[size];
		char* bufx = new char[size];
		read_raw(address, buf, size);
		// compiler warnings expected:
		value = *((int*)buf);
		if(!little_endian_)
			for(unsigned int i = 0; i < size; i++)
				bufx[i] = buf[size-1-i];
		else
			for(unsigned int i = 0; i < size; i++)
				bufx[i] = buf[i];
		delete buf;
		value = *((int*)bufx);
		delete bufx;
	}
	return value;
}
int Binfile::read_int(unsigned int address){return read_int(address, 4);}
unsigned int Binfile::get_end(void){return end_;}

Disasm::Disasm(std::string infile_path, unsigned int offset, unsigned int end)
{
	binfile_ = new Binfile(infile_path, offset, end);
	offset_ = offset;
	end_ = binfile_->get_end();
	ranges_ = { 0x080000, 0x0800ffff, 0x2000000, 0x2000ffff};
	// TODO: find a better, more generic way to add these ranges
	std::cout << "Disasm() was called!" << std::endl;
}

// This is called delegation. It's why we need C++11
Disasm::Disasm(std::string infile_path, unsigned int offset):
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

void Disasm::find_vectors(void)
{
	AddrList::iterator pos;
	unsigned int addr = offset_;
	bool vector_end = false;
	while(not vector_end)
	{
		pos = vectors_.end();
		vector_end = true;
		unsigned int word = 0;
		word = (unsigned int)binfile_->read_int(addr);
		if( (word >= ranges_.flash_start && word <= ranges_.flash_end)
				|| (word >= ranges_.ram_start && word <= ranges_.ram_end)
				|| word == 0 )
		{
			vector_end = false;
			vectors_.insert(pos, addr);
		}
		addr += 4;
	}

}

void Disasm::disassemble(void)
{
	unsigned int read_addr = offset_;
	char buf[4]; // read buffer
	while( read_addr <= end_ - 4 )
	{
		// TODO:
		// Mechanism to turn known data bytes (i.e. vectors) directly into PsOp Objects.
		// TODO:
		// cover edge case with (read_addr == end_ - 2)
		// TODO:
		// Turn Memlist / program_ into a separate class?

		std::shared_ptr<Op> current_word = 0;

		//if(addr in psop list)
		if( std::find(vectors_.begin(), vectors_.end(), read_addr) != vectors_.end() )
		{
			int value = binfile_->read_int(read_addr, 4);
			current_word = std::make_shared<PsOp>(read_addr, value, 4, ".vector");
			read_addr += 4;
		}
		//else if(addr in word list, halfword list, ...)
		else
		{
			binfile_->read_raw(read_addr, buf, 4);
			current_word = std::make_shared<RlOp>(read_addr, (unsigned char*)buf, 4);
			//std::cout << "in Disasm()" << current_word << std::endl;
			if(current_word->get_size() == 0)
			{
				int value = binfile_->read_int(read_addr, 4);
				current_word = std::make_shared<PsOp>(read_addr, value);
				read_addr += 4;
			}
			else if(current_word->get_size() == 2) read_addr += 2;
			else if(current_word->get_size() == 4) read_addr += 4;
			else
			{
				std::cerr << "ERROR: current_word has a bad size!" << std::endl;
			}
		}
		Memlist::iterator pos = program_.end();
		program_.insert(pos, current_word);
		// program_.sort(Op::comp_addr_ptr);
		// not needed when everything is appended at the back
	}
}

int Disasm::write_disasm()
{
	Memlist::iterator pos = program_.begin();
	std::cout << "writing disassembly..." << std::endl;
	while(pos != program_.end()) std::cout << *pos++ << std::endl;
	return 0;
}





