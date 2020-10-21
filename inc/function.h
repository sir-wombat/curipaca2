#ifndef FUNCTION_H
#define FUNCTION_H

#include <string>
#include <list>
#include <memory>

class Function
{
public:
	Function(unsigned int address);
	Function(unsigned int address, std::string reason);
	~Function();
	unsigned int get_address(void);
	std::string get_reason(void);
	friend std::ostream& operator<<(std::ostream&, Function*);
	std::string str(void);

private:
	unsigned int address_;
	std::string reason_;
};

inline std::ostream& operator<<(std::ostream& os, Function* fn)
{
  os << fn->str();
  return os;
}


typedef std::list<std::shared_ptr<Function>> Fnlist;

#endif // FUNCTION_H
