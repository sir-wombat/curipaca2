// own libs:
#include <prut.h>

// own includes:
#include <iostream>
#include <fstream>
#include <string>

int main(void)
{
	// decoration:
	// std::cout << "\033[2J\033[1;1H"; // not needed within eclipse
	std::cout << "\n\tCuripaca Decompiler\n\n";

	/////////////////////////////////////////////
	// write files
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
