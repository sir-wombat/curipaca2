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

	virtual unsigned int get_address(void)const;
	virtual unsigned int get_size(void)const;
	friend std::ostream& operator<<(std::ostream&, Op*);
	bool lower_address(const Op&) const;

	static bool comp_addr(const Op&, const Op&);
	static bool comp_addr_ptr(std::shared_ptr<Op>, std::shared_ptr<Op>);

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
	RlOp(unsigned long int address, const unsigned char* bytes, size_t size);
	~RlOp(void);

private:
	cs_insn* csop_;

	virtual std::string print(void)const;

};

class PsOp : public Op
{
public:
	PsOp(unsigned int address, int value, unsigned int size,
			std::string comment);
	PsOp(unsigned int address, int value);
	PsOp();
	~PsOp(void);

	virtual unsigned int get_value(void);

private:
	int value_;
	std::string comment_;
	virtual std::string print(void)const;
};

typedef std::list<std::shared_ptr<Op>> Memlist;


#endif // OP_H
