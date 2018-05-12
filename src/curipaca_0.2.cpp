
// Capstone includes:
#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

// Eigene Libs:
#include <prut.h>

// Eigene Includes:
#include <iostream>
#include <fstream>
#include <string>
using namespace std; // TODO: Weg damit!



#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int main(void)
{
	//Dekoblock:
	// std::cout << "\033[2J\033[1;1H"; // not needed within eclipse
	std::cout << "\n\tCuripaca Decompiler\n\n";
	/////////////////////////////////////////////
	// Capstone Block:
	std::cout << "Capstone Test:" << std::endl;
	csh handle;
	cs_insn *insn;
	size_t count;

	if( cs_open(CS_ARCH_X86, CS_MODE_64, &handle) )
	{
		printf( "ERROR: Failed to initialize engine!\n" );
		return -1;
	}
	count = cs_disasm(handle, (unsigned char *)CODE, sizeof(CODE) - 1,
			0x1000, 0, &insn);
	if(count)
	{
		size_t j;
		for (j = 0; j < count; j++)
		{
			printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address,
					insn[j].mnemonic, insn[j].op_str);
		}
		cs_free(insn, count);
	}
	else
	{
		printf("ERROR: Failed to disassemble given code!\n");
	}
	cs_close(&handle);

	std::cout << std::endl;


	/////////////////////////////////////////////
	// Dateien schreiben
	/*
	ofstream myfile;
	myfile.open ("Testordner/example.txt");
	myfile << "Writing this to a file.\n";
	myfile.close();
	*/
	// Dateien lesen
	/*
	string line;
	ifstream myfile2 ("Testordner/example2.txt");
	if( myfile2.is_open() )
	{
		while ( getline(myfile2,line) )
		{
			cout << line << '\n';
		}
		myfile2.close();
	}
	else
	{
		cout << "Unable to open file";
	}
	*/

	// Testreihen/demsys-O3.bin
	Prut testfall01("Testreihen/demsys-O3.bin", 0x08000000);
	if(!testfall01.disassemble())
	{
		std::cout << "Dissassembly worked." << std::endl;
	}
	else
	{
		std::cout << "Disassembly failed. Trying something else..." << std::endl;
		Prut testfall02("../Testreihen/demsys-O3.bin", 0x08000000);
		if(!testfall02.disassemble())
		{
			std::cout << "now it worked" << std::endl;
		}
		else
		{
			std::cout << "Failed, too. Giving up now." << std::endl;
		}
	}

    return 0;
}
