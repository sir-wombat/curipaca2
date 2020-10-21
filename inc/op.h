#ifndef OP_H
#define OP_H

#include <string>
#include <list>
#include <capstone/capstone.h>

#include <memory> // for std::shared_ptr

extern int global_op_count;

///////////////////////////////////////////////////////////////////////////////
// Op is an abstract class. Things are either Real Ops or Pseudo Ops.
// Therefore: Op::real_op(void) = 0;
class Op
{
public:
	Op(void);
	virtual ~Op(void);

	unsigned int get_address(void)const;
	unsigned int get_size(void)const;
	friend std::ostream& operator<<(std::ostream&, Op*);

	virtual bool real_op(void)const = 0;

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

///////////////////////////////////////////////////////////////////////////////
class RlOp : public Op
{
public:
	RlOp(unsigned long int address, const unsigned char* bytes, size_t size);
	~RlOp(void);
	bool real_op(void)const{return true;}
	const cs_insn* get_csop(void);

private:
	cs_insn* csop_;

	virtual std::string print(void)const;

};

///////////////////////////////////////////////////////////////////////////////
class PsOp : public Op
{
public:
	PsOp(unsigned int address, unsigned int value, unsigned int size,
			std::string comment);
	PsOp(unsigned int address, int value);
	PsOp();
	~PsOp(void);
	bool real_op(void)const{return false;}
	unsigned int get_value(void);

private:
	unsigned int value_;
	std::string comment_;
	virtual std::string print(void)const;
};

///////////////////////////////////////////////////////////////////////////////
typedef std::list<std::shared_ptr<Op>> Memlist;

bool equiv_rlops(std::shared_ptr<RlOp> op1, std::shared_ptr<RlOp> op2);
bool equiv_psops(std::shared_ptr<PsOp> op1, std::shared_ptr<PsOp> op2);
bool equiv_ops(std::shared_ptr<Op> op1, std::shared_ptr<Op> op2);
bool equiv_memlists(Memlist& liste1, Memlist& liste2);


#endif // OP_H
