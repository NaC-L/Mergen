#ifndef LIFTERCLASS_H
#define LIFTERCLASS_H
#include "FunctionSignatures.h"
#include "GEPTracker.h"
#include "includes.h"

#define DEFINE_FUNCTION(name) void lift_##name()

class lifterClass {
public:
  lifterClass(IRBuilder<>& irbuilder) : builder(irbuilder) {};
  IRBuilder<>& builder;

  bool run = 0;      // we may set 0 so to trigger jumping to next basic block
  bool finished = 0; // finished, unfinished, unreachable
  bool isUnreachable = 0;

  ZydisDisassembledInstruction* instruction = nullptr;
  lifterMemoryBuffer buffer;
  BBInfo blockInfo;

  unordered_map<Flag, Value*> FlagList;
  RegisterMap Registers;

  Value* memory;
  Value* TEB;

  void liftInstruction();
  void liftInstructionSemantics();
  void branchHelper(Value* condition, string instname, int numbered,
                    bool reverse = false);
  void Init_Flags();
  Value* setFlag(Flag flag, Value* newValue = nullptr);
  Value* getFlag(Flag flag);
  RegisterMap getRegisters();
  void setRegisters(RegisterMap newRegisters);
  ReverseRegisterMap flipRegisterMap();
  RegisterMap InitRegisters(Function* function, ZyanU64 rip);
  Value* GetValueFromHighByteRegister(int reg);
  Value* GetRegisterValue(int key);
  Value* SetValueToHighByteRegister(int reg, Value* value);
  Value* SetValueToSubRegister_8b(int reg, Value* value);
  Value* SetValueToSubRegister_16b(int reg, Value* value);
  void SetRegisterValue(int key, Value* value);
  void SetRFLAGSValue(Value* value);
  PATH_info solvePath(Function* function, uint64_t& dest, Value* simplifyValue);
  void replaceAllUsesWithandReplaceRMap(Value* v, Value* nv,
                                        ReverseRegisterMap rVMap);
  void simplifyUsers(Value* newValue, DataLayout& DL,
                     ReverseRegisterMap flippedRegisterMap);
  Value* popStack();
  void pushFlags(vector<Value*> value, string address);
  vector<Value*> GetRFLAGS();
  Value* GetOperandValue(ZydisDecodedOperand& op, int possiblesize,
                         string address = "");
  Value* SetOperandValue(ZydisDecodedOperand& op, Value* value,
                         string address = "");
  void callFunctionIR(string functionName,
                      funcsignatures::functioninfo* funcInfo);
  Value* GetEffectiveAddress(ZydisDecodedOperand& op, int possiblesize);
  vector<Value*> parseArgs(funcsignatures::functioninfo* funcInfo);
  FunctionType* parseArgsType(funcsignatures::functioninfo* funcInfo,
                              LLVMContext& context);
  Value* GetRFLAGSValue();
  DEFINE_FUNCTION(movsb);
  DEFINE_FUNCTION(movaps);
  DEFINE_FUNCTION(mov);
  DEFINE_FUNCTION(cmovbz);
  DEFINE_FUNCTION(cmovnbz);
  DEFINE_FUNCTION(cmovz);
  DEFINE_FUNCTION(cmovnz);
  DEFINE_FUNCTION(cmovl);
  DEFINE_FUNCTION(cmovnl);
  DEFINE_FUNCTION(cmovb);
  DEFINE_FUNCTION(cmovnb);
  DEFINE_FUNCTION(cmovns);
  DEFINE_FUNCTION(cmovs);
  DEFINE_FUNCTION(cmovnle);
  DEFINE_FUNCTION(cmovle);
  DEFINE_FUNCTION(cmovo);
  DEFINE_FUNCTION(cmovno);
  DEFINE_FUNCTION(cmovp);
  DEFINE_FUNCTION(cmovnp);
  //
  DEFINE_FUNCTION(call);
  DEFINE_FUNCTION(ret);
  DEFINE_FUNCTION(jmp);
  DEFINE_FUNCTION(jnz);
  DEFINE_FUNCTION(jz);
  DEFINE_FUNCTION(js);
  DEFINE_FUNCTION(jns);
  DEFINE_FUNCTION(jle);
  DEFINE_FUNCTION(jl);
  DEFINE_FUNCTION(jnl);
  DEFINE_FUNCTION(jnle);
  DEFINE_FUNCTION(jbe);
  DEFINE_FUNCTION(jb);
  DEFINE_FUNCTION(jnb);
  DEFINE_FUNCTION(jnbe);
  DEFINE_FUNCTION(jo);
  DEFINE_FUNCTION(jno);
  DEFINE_FUNCTION(jp);
  DEFINE_FUNCTION(jnp);
  //
  DEFINE_FUNCTION(sbb);
  DEFINE_FUNCTION(rcl);
  DEFINE_FUNCTION(rcr);
  DEFINE_FUNCTION(not );
  DEFINE_FUNCTION(neg);
  DEFINE_FUNCTION(sar);
  DEFINE_FUNCTION(shr);
  DEFINE_FUNCTION(shl);
  DEFINE_FUNCTION(bswap);
  DEFINE_FUNCTION(cmpxchg);
  DEFINE_FUNCTION(xchg);
  DEFINE_FUNCTION(shld);
  DEFINE_FUNCTION(shrd);
  DEFINE_FUNCTION(lea);
  DEFINE_FUNCTION(add_sub);
  void lift_imul2(bool isSigned);
  DEFINE_FUNCTION(imul);
  DEFINE_FUNCTION(mul);
  DEFINE_FUNCTION(div2);
  DEFINE_FUNCTION(div);
  DEFINE_FUNCTION(idiv2);
  DEFINE_FUNCTION(idiv);
  DEFINE_FUNCTION(xor);
  DEFINE_FUNCTION(or);
  DEFINE_FUNCTION(and);
  DEFINE_FUNCTION(rol);
  DEFINE_FUNCTION(ror);
  DEFINE_FUNCTION(inc_dec);
  DEFINE_FUNCTION(push);
  DEFINE_FUNCTION(pushfq);
  DEFINE_FUNCTION(pop);
  DEFINE_FUNCTION(popfq);
  DEFINE_FUNCTION(adc);
  DEFINE_FUNCTION(xadd);
  DEFINE_FUNCTION(test);
  DEFINE_FUNCTION(cmp);
  DEFINE_FUNCTION(rdtsc);
  DEFINE_FUNCTION(cpuid);
  //
  DEFINE_FUNCTION(setnz);
  DEFINE_FUNCTION(seto);
  DEFINE_FUNCTION(setno);
  DEFINE_FUNCTION(setnb);
  DEFINE_FUNCTION(setbe);
  DEFINE_FUNCTION(setnbe);
  DEFINE_FUNCTION(setns);
  DEFINE_FUNCTION(setp);
  DEFINE_FUNCTION(setnp);
  DEFINE_FUNCTION(setb);
  DEFINE_FUNCTION(sets);
  DEFINE_FUNCTION(stosx);
  DEFINE_FUNCTION(setz);
  DEFINE_FUNCTION(setnle);
  DEFINE_FUNCTION(setle);
  DEFINE_FUNCTION(setnl);
  DEFINE_FUNCTION(setl);
  DEFINE_FUNCTION(bt);
  DEFINE_FUNCTION(btr);
  DEFINE_FUNCTION(bts);
  DEFINE_FUNCTION(bsr);
  DEFINE_FUNCTION(bsf);
  DEFINE_FUNCTION(btc);
  DEFINE_FUNCTION(lahf);
  DEFINE_FUNCTION(sahf);
  DEFINE_FUNCTION(std);
  DEFINE_FUNCTION(stc);
  DEFINE_FUNCTION(cmc);
  DEFINE_FUNCTION(clc);
  DEFINE_FUNCTION(cld);
  DEFINE_FUNCTION(cli);
  DEFINE_FUNCTION(cwd);
  DEFINE_FUNCTION(cdq);
  DEFINE_FUNCTION(cqo);
  DEFINE_FUNCTION(cbw);
  DEFINE_FUNCTION(cwde);
  DEFINE_FUNCTION(cdqe);
};
extern vector<lifterClass*> lifters;
#endif // LIFTERCLASS_H