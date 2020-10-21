#if __cplusplus <= 201103L
  #error This library needs at least a C++11 compliant compiler
#endif

#include <disasm.h>
#include <algorithm> // for std::find
#include <sstream>   // for error message with hex formatted address
#include <iomanip> // für std::setw

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
			<< " bytes long." << std::endl;
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

unsigned int Binfile::read_int(unsigned int address, unsigned int size)
{
	unsigned int value = 0;
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
		value = *((unsigned int*)bufx);
		delete bufx;
	}
	return value;
}
unsigned int Binfile::read_int(unsigned int address){return read_int(address, 4);}
unsigned int Binfile::get_end(void){return end_;}

Disasm::Disasm(std::string infile_path, unsigned int offset, unsigned int end)
{
	binfile_ = new Binfile(infile_path, offset, end);
	offset_ = offset;
	end_ = binfile_->get_end();
	ranges_ = { 0x080000, 0x0800ffff, 0x2000000, 0x2000ffff};
	// TODO: find a better, more generic way to add these ranges
	//std::cout << "Disasm() was called!" << std::endl;
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
	//std::cout << "~Disasm() was called!" << std::endl;
}

DataMap Disasm::find_vectors(void)
{
	AddrList::iterator pos;
	DataMap vectors;
	unsigned int addr = offset_;
	bool vector_end = false;
	while(not vector_end)
	{
		//pos = vectors_.end();
		vector_end = true;
		unsigned int word = 0;
		word = binfile_->read_int(addr);
		if( (word >= ranges_.flash_start && word <= ranges_.flash_end)
				|| (word >= ranges_.ram_start && word <= ranges_.ram_end)
				|| word == 0 )
		{
			vector_end = false;
			//vectors_.insert(pos, addr);
			vectors[addr] = std::make_shared<PsOp>(addr, word, 4, ".vector");
		}
		addr += 4;
	}
	return vectors;
}

std::shared_ptr<Op> Disasm::parse_address(unsigned int address, unsigned short length)
{
	std::shared_ptr<Op> current_word = 0;
	char buf[length]; // read buffer
	binfile_->read_raw(address, buf, length);
	current_word = std::make_shared<RlOp>(address, (unsigned char*)buf, length);
	//std::cout << "in Disasm::parse_address()" << current_word << std::endl;
	if(current_word->get_size() == 0)
	{
		// TODO: Maybe increment by single bytes,
		// in order to not miss the next proper Op?
		unsigned int value = binfile_->read_int(address, length);
		current_word = std::make_shared<PsOp>(address, value);
	}
	return current_word;
}

/* Neue Disassemble Struktur:
 *
 * 1. Es gibt eine Funktion dis_iter() die genau
 * eine Iteration des Disassemblies durchführt. Diese verändert
 * den Zustand des Disasm Objekts und gibt als Rückgabewert als
 * Int Wert zurück ob/wie viel Veränderung es gegenüber der vorigen
 * Iteration gab.
 *
 */


void Disasm::disassemble(void)
{
	//initial known data:
	known_data_ = find_vectors();
	//loop
	int loopcount = 0;
	std::cout << "Running initial iteration (number 0)..." << std::endl;
	std::cout << "global_op_count = " << global_op_count << std::endl;
	while( loopcount < 10 && dis_iter() )
	{
		std::cout << "global_op_count = " << global_op_count << std::endl;
		search_data();
		loopcount++;
		std::cout << "Running iteration number " << loopcount << " ..." << std::endl;
	}
	std::cout << "global_op_count = " << global_op_count << std::endl;
}

int Disasm::dis_iter(void)
{
	Memlist program; // new list for this iteration
	DataMap known_data = find_vectors(); // new map for the next iteration
	unsigned int read_addr = offset_; // start at addr 0+offset
	unsigned short length = 0; // length of next read
	while(read_addr < end_)
	{
		std::shared_ptr<Op> current_word = 0;
		// 1. check how long the next read should be
		//std::cout << "offset_ = " << offset_ << "; read_addr = " << read_addr << "; end_ = " << end_ << ";" << std::endl;
		if(end_-read_addr >= 3) length = 4;
		else if(end_-read_addr == 1) length = 2;
		else
		{
			std::cerr << "ERROR: Odd amount of bytes left over!" << std::endl;
			break;
		}

		// 2. check if current read_addr is a known pseudo_op:
		try
		{
			std::shared_ptr<PsOp> old_psop = known_data_.at(read_addr);
			// the above throws an OOR exception if there is nothing at read_addr
			// plausibility check:
			unsigned int old_value = old_psop->get_value();
			unsigned int new_value = binfile_->read_int(read_addr, old_psop->get_size());
			if( old_value != new_value )
			{
				// check failed:
				std::stringstream ss;
				ss << "Error constant at 0x" << std::hex
				   << std::setfill('0') << std::setw(8) << read_addr
				   << " apparently changed!" << std::endl;
				std::string outstring = ss.str();
				throw std::invalid_argument( outstring );
			}
			// check passed:
			current_word = std::static_pointer_cast<Op>(old_psop);
			read_addr += current_word->get_size();
		}
		catch(const std::out_of_range& oor)
		{
			// no known PsOp at this read_addr
			// current_word is still 0
		}
		// 3. if no pseudo_op expected at read_addr, parse as real_op:
		if( current_word == 0 )
		{
			current_word = parse_address(read_addr, length);
			read_addr += current_word->get_size();
			// TODO: check if this operation contains any information
			// about the location of any data
		}
		//Memlist::iterator pos = program.end();
		program.insert(program.end(), current_word);
		// program_.sort(Op::comp_addr_ptr);
		// not needed when everything is appended at the back
	}

	known_data_ = known_data; // TODO: Muss known_data bzw. known_data_ ordentlich gelöscht werden?
	if(program_.empty())
	{
		program_ = program;
		return 1;
	}
	if( not equiv_memlists(program, program_) )
	{
		program_ = program;
		return 1;
	}
	// TODO: Muss hier eigentlich program anschließend ordentlich gelöscht werden?
	// bzw. muss das ursprüngliche program_ gelöscht werden?
	// TODO: Memoryleaks entfernen!
	return 0;
}

void Disasm::search_data(void)
{
	DataMap known_data;
	Memlist::iterator pos = program_.begin();
	while(pos != program_.end())
	{
		if( (*pos)->real_op() )
		{
			// We have an actual (capstone-)operation
			// now we need to check wether it contains
			// hints about a data address
			// hints could be:
			//	- load ops
			//	- tbb / tbh -> need separate function
		}
		pos++;
	}
	return;
}

int Disasm::print_disasm()
{
	Memlist::iterator pos = program_.begin();
	std::cout << "writing disassembly..." << std::endl;
	while(pos != program_.end()) std::cout << *pos++ << std::endl;
	return 0;
}

int Disasm::write_disasm(std::string outfile_path)
{
	// TODO: Error handling
	std::ofstream outfile;
	outfile.open(outfile_path);
	Memlist::iterator pos = program_.begin();
	while(pos != program_.end())
		outfile << *pos++ << std::endl;
	outfile.close();
	return 0;
}



