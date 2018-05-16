#ifndef OP_H
#define OP_H

#include <string>
#include <list>
#include <capstone/capstone.h>

#include <memory> // for std::shared_ptr

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

class RlOp : public Op
{
public:
	RlOp(unsigned long int address, const unsigned char* bytes);
	~RlOp(void);

private:
	cs_insn* csop_;

	virtual std::string print(void)const;

};

class PsOp : public Op
{
public:
	PsOp(unsigned int address, unsigned int value, unsigned int size,
			std::string comment);
	PsOp(unsigned int address, unsigned int value);
	PsOp();

	~PsOp(void);

	virtual unsigned int get_value(void);

private:
	unsigned int value_;
	std::string comment_;
	virtual std::string print(void)const;
};

//typedef std::list<Op*> Memlist;
typedef std::list<std::shared_ptr<Op>> Memlist;


#endif // OP_H
