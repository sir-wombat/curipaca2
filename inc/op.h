#ifndef OP_H
#define OP_H

#include <string>
#include <list>
//#include <iostream>

class Op
{
public:
	Op(void);
	virtual ~Op(void);

	virtual unsigned int get_address(void);
	virtual unsigned int get_size(void);
	friend std::ostream& operator<<(std::ostream&, Op*);

protected:
	unsigned int address_;
	unsigned int size_;

private:
	virtual std::string print(void)const;
};

inline std::ostream& operator<<(std::ostream& os, Op* op)
{
  os << op->print();
  return os;
}

//class RlOp : public Op
//{

//};

class PsOp : public Op
{
public:
	PsOp(unsigned int address, unsigned int value, unsigned int size,
			std::string comment);
	PsOp(unsigned int address, unsigned int value);
	PsOp();

	~PsOp(void);

	virtual unsigned int get_value(void);
	virtual unsigned int get_address(void);
	virtual unsigned int get_size(void);

private:
	unsigned int value_;
	std::string comment_;
	virtual std::string print(void)const;
};

typedef std::list<Op*> Memlist;



#endif // OP_H
