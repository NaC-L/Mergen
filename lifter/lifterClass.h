#ifndef LIFTERCLASS_H
#define LIFTERCLASS_H
#include "FunctionSignatures.h"
#include "GEPTracker.h"
#include "PathSolver.h"
#include "includes.h"
#include "utils.h"
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/DomConditionCache.h>
#include <llvm/Analysis/SimplifyQuery.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/KnownBits.h>
#include <set>

#ifndef DEFINE_FUNCTION
#define DEFINE_FUNCTION(name) void lift_##name()
#endif

struct InstructionKey {
  Value* operand1;
  union {
    Value* operand2;
    Type* destType;
  };

  InstructionKey() : operand1(nullptr), operand2(nullptr){};

  InstructionKey(Value* operand1, Value* operand2)
      : operand1(operand1), operand2(operand2){};

  InstructionKey(Value* operand1, Type* destType)
      : operand1(operand1), destType(destType){};

  bool operator==(const InstructionKey& other) const {
    if (operand1 != other.operand1)
      return false;
    return operand2 == other.operand2;
  }
  struct InstructionKeyInfo {
    // Custom hash function
    static inline unsigned getHashValue(const InstructionKey& key) {

      auto h2 = llvm::hash_value(key.operand1);
      auto h3 = llvm::hash_value(key.destType);
      return llvm::hash_combine(h2, h3);
    }

    // Equality function
    static inline bool isEqual(const InstructionKey& lhs,
                               const InstructionKey& rhs) {
      return lhs == rhs;
    }

    // Define empty and tombstone keys
    static inline InstructionKey getEmptyKey() {
      return InstructionKey(nullptr, static_cast<Value*>(nullptr));
    }

    static inline InstructionKey getTombstoneKey() {
      return InstructionKey(nullptr, static_cast<Value*>(nullptr));
    }
  };
};

class InstructionCache {
public:
  InstructionCache() {}

  void insert(uint8_t opcode, const InstructionKey& key, Value* value) {
    // Insert the key-value pair into the cache for the given opcode
    opcodeCaches[opcode].insert({key, value});
  }

  Value* lookup(uint8_t opcode, const InstructionKey& key) const {
    auto itOpcode = opcodeCaches.find(opcode);
    if (itOpcode != opcodeCaches.end()) {
      auto it = itOpcode->second.find(key);
      if (it != itOpcode->second.end()) {
        return it->second;
      }
    }
    return nullptr; // Handle cache miss appropriately
  }

private:
  using CacheMap = llvm::DenseMap<InstructionKey, Value*,
                                  InstructionKey::InstructionKeyInfo>;
  std::unordered_map<uint8_t, CacheMap>
      opcodeCaches; // Dynamic allocation of CacheMaps
};

class floatingPointValue {
public:
  Value* v1;
  Value* v2;
};

class RegisterManager {
public:
  enum RegisterIndex {
    RAX_ = 0,
    RCX_,
    RDX_,
    RBX_,
    RSP_,
    RBP_,
    RSI_,
    RDI_,
    R8_,
    R9_,
    R10_,
    R11_,
    R12_,
    R13_,
    R14_,
    R15_,
    RIP_,
    RFLAGS_,
    REGISTER_COUNT // Total number of registers
  };
  std::array<Value*, REGISTER_COUNT> vec;

  RegisterManager() {}
  RegisterManager(const RegisterManager& other) : vec(other.vec) {}

  // Overload the [] operator for getting register values

  int getRegisterIndex(const ZydisRegister key) const {

    switch (key) {
    case ZYDIS_REGISTER_RIP: {
      return RIP_;
    }
    case ZYDIS_REGISTER_RFLAGS: {
      return RFLAGS_;
    }
    default: {
      // For ordered registers RAX to R15, map directly by offset from RAX
      assert(key >= ZYDIS_REGISTER_RAX && key <= ZYDIS_REGISTER_R15 &&
             "Key must be between RAX and R15");

      return key - ZYDIS_REGISTER_RAX;
    }
    }
  }

  llvm::Value*& operator[](ZydisRegister key) {
    int index = getRegisterIndex(key);
    return vec[index];
  }
};

struct BBInfo {
  uint64_t runtime_address;
  llvm::BasicBlock* block;

  BBInfo(){};

  BBInfo(uint64_t runtime_address, llvm::BasicBlock* block)
      : runtime_address(runtime_address), block(block) {}
};

class LazyFlag {
public:
  std::optional<llvm::Value*> value;

  std::function<llvm::Value*()> calculation; // calculate value

  LazyFlag() : value(nullptr), calculation(nullptr) {}
  LazyFlag(llvm::Value* val) : value(val), calculation(nullptr) {}
  LazyFlag(std::function<llvm::Value*()> calc)
      : calculation(calc), value(std::nullopt) {}

  // get value, calculate if doesnt exist
  llvm::Value* get() {
    if (!value.has_value() && calculation) {

      value = calculation();
    }

    return value.value_or(nullptr);
  }

  // Set a new value directly, bypassing lazy evaluation
  void set(llvm::Value* newValue) {
    value = newValue;
    calculation = nullptr; // Disable lazy evaluation when setting directly
  }
  void setCalculation(const std::function<llvm::Value*()> calc) {
    calculation = calc;
    value = std::nullopt; // Reset the stored value
  }
};

class lifterClass {
public:
  llvm::IRBuilder<>& builder;
  BBInfo blockInfo;

  bool run = 0;      // we may set 0 so to trigger jumping to next basic block
  bool finished = 0; // finished, unfinished, unreachable
  bool isUnreachable = 0;
  uint32_t counter = 0;
  // unique

  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions;
  llvm::DenseMap<uint64_t, ValueByteReference> buffer;
  using flagManager = std::array<LazyFlag, FLAGS_END>;
  // llvm::DenseMap<Value*, flagManager> flagbuffer;

  flagManager FlagList;
  RegisterManager Registers;

  llvm::DomConditionCache* DC = new DomConditionCache();

  unsigned int instct = 0;
  llvm::SimplifyQuery* cachedquery;

  llvm::DominatorTree* DT;
  llvm::BasicBlock* lastBB = nullptr;
  unsigned int BIlistsize = 0;

  std::map<int64_t, int64_t> pageMap;
  std::vector<llvm::BranchInst*> BIlist;
  // DenseMap<InstructionKey, Value*, InstructionKey::InstructionKeyInfo>
  // cache;
  InstructionCache cache;
  struct GEPinfo {
    Value* addr;
    uint8_t type;
    bool TEB;

    GEPinfo() : addr(nullptr), type(0), TEB(0){};

    GEPinfo(Value* addr, uint8_t type, bool TEB)
        : addr(addr), type(type), TEB(TEB){};

    bool operator==(const GEPinfo& other) const {
      if (addr != other.addr)
        return false;
      if (type != other.type)
        return false;
      return TEB == other.TEB;
    }

    struct GEPinfoKeyInfo {
      // Custom hash function
      static inline unsigned getHashValue(const GEPinfo& key) {
        auto h2 = llvm::hash_value(key.addr);
        auto h3 = llvm::hash_value(key.type + key.TEB);
        return llvm::hash_combine(h2, h3);
      }

      // Equality function
      static inline bool isEqual(const GEPinfo& lhs, const GEPinfo& rhs) {
        return lhs == rhs;
      }

      // Define empty and tombstone keys
      static inline GEPinfo getEmptyKey() { return GEPinfo(nullptr, 0, 0); }

      static inline GEPinfo getTombstoneKey() {
        return GEPinfo(nullptr, 255, 0);
      }
    };
  };
  DenseMap<GEPinfo, Value*, GEPinfo::GEPinfoKeyInfo> GEPcache;
  std::vector<llvm::Instruction*> memInfos;

  // global
  llvm::Value* memory;
  llvm::Value* TEB;
  llvm::Function* fnc;

  lifterClass(llvm::IRBuilder<>& irbuilder) : builder(irbuilder){};

  lifterClass(const lifterClass& other)
      : builder(other.builder), // Reference copied directly
        blockInfo(
            other.blockInfo), // Assuming BBInfo has a proper copy constructor
        run(other.run), finished(other.finished), counter(other.counter),
        isUnreachable(other.isUnreachable),
        instruction(other.instruction), // Shallow copy of the pointer
        assumptions(other.assumptions), // Deep copy of assumptions
        buffer(other.buffer),
        FlagList(other.FlagList), // Deep copy handled by unordered_map's copy
                                  // constructor
        Registers(other.Registers),     // Assuming RegisterManager has a copy
                                        // constructor
        DC(other.DC),                   // Deep copy of DC
        instct(other.instct),
        cachedquery(other.cachedquery), // Assuming raw pointer, copied directly
        DT(other.DT),                   // Assuming pointer, copied directly
        lastBB(other.lastBB), BIlistsize(other.BIlistsize),
        pageMap(other.pageMap), // Deep copy handled by map's copy constructor
        BIlist(other.BIlist), // Deep copy handled by vector's copy constructor
        cache(other.cache), // Deep copy handled by DenseMap's copy constructor
        memInfos(
            other.memInfos),  // Deep copy handled by vector's copy constructor
        memory(other.memory), // Shallow copy of the pointer
        TEB(other.TEB),       // Shallow copy of the pointer
        fnc(other.fnc)        // Shallow copy of the pointer
  {}

  void liftInstruction();
  void liftInstructionSemantics();
  void branchHelper(llvm::Value* condition, const std::string& instname,
                    const int numbered, const bool reverse = false);

  // init
  void Init_Flags();
  void initDomTree(llvm::Function& F) { DT = new DominatorTree(F); }
  // end init

  // getters-setters
  llvm::Value* setFlag(const Flag flag, llvm::Value* newValue = nullptr);
  void setFlag(const Flag flag, std::function<llvm::Value*()> calculation);
  llvm::Value* getFlag(const Flag flag);
  void InitRegisters(llvm::Function* function, ZyanU64 rip);
  llvm::Value* GetValueFromHighByteRegister(const ZydisRegister reg);
  llvm::Value* GetRegisterValue(const ZydisRegister key);
  llvm::Value* SetValueToHighByteRegister(const ZydisRegister reg,
                                          llvm::Value* value);
  llvm::Value* SetValueToSubRegister_8b(const ZydisRegister reg,
                                        llvm::Value* value);
  llvm::Value* SetValueToSubRegister_16b(const ZydisRegister reg,
                                         llvm::Value* value);
  void SetRegisterValue(const ZydisRegister key, llvm::Value* value);
  void SetRFLAGSValue(llvm::Value* value);
  PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                      llvm::Value* simplifyValue);
  llvm::Value* popStack(int size);
  void pushFlags(const std::vector<llvm::Value*>& value,
                 const std::string& address);
  std::vector<llvm::Value*> GetRFLAGS();

  llvm::Value* GetOperandValue(const ZydisDecodedOperand& op,
                               const int possiblesize,
                               const std::string& address = "");
  llvm::Value* SetOperandValue(const ZydisDecodedOperand& op,
                               llvm::Value* value,
                               const std::string& address = "");
  llvm::Value* GetRFLAGSValue();
  // end getters-setters
  // misc
  llvm::Value* callFunctionIR(const std::string& functionName,
                              funcsignatures::functioninfo* funcInfo);
  llvm::Value* GetEffectiveAddress(const ZydisDecodedOperand& op,
                                   const int possiblesize);
  std::vector<llvm::Value*> parseArgs(funcsignatures::functioninfo* funcInfo);
  llvm::FunctionType* parseArgsType(funcsignatures::functioninfo* funcInfo,
                                    llvm::LLVMContext& context);

  llvm::Value* computeSignFlag(Value* value);
  llvm::Value* computeZeroFlag(Value* value);
  llvm::Value* computeParityFlag(Value* value);
  llvm::Value* computeAuxFlag(Value* Lvalue, Value* Rvalue, Value* result);
  llvm::Value* computeOverflowFlagSbb(Value* Lvalue, Value* Rvalue, Value* cf,
                                      Value* sub);

  llvm::Value* computeOverflowFlagSub(Value* Lvalue, Value* Rvalue, Value* sub);
  llvm::Value* computeOverflowFlagAdd(Value* Lvalue, Value* Rvalue, Value* add);
  llvm::Value* computeOverflowFlagAdc(Value* Lvalue, Value* Rvalue, Value* cf,
                                      Value* add);
  // end misc
  // analysis
  llvm::KnownBits analyzeValueKnownBits(Value* value, Instruction* ctxI);

  llvm::Value* solveLoad(LoadInst* load);

  llvm::SimplifyQuery createSimplifyQuery(Instruction* Inst);

  void RegisterBranch(BranchInst* BI) {
    //
    BIlist.push_back(BI);
  }

  DominatorTree* getDomTree() { return DT; }

  void updateDomTree(Function& F) {
    // should only recalculate if we

    auto getLastBB = &(F.back());

    if (getLastBB != lastBB)
      DT->recalculate(F);

    lastBB = getLastBB;
  }

  void markMemPaged(const int64_t start, const int64_t end) {
    //
    pageMap[start] = end;
  }

  bool isMemPaged(const int64_t address) {
    auto it = pageMap.upper_bound(address);
    if (it == pageMap.begin())
      return false;
    --it;
    return address >= it->first && address < it->second;
  }

  set<APInt, APIntComparator> getPossibleValues(const llvm::KnownBits& known,
                                                unsigned max_unknown);

  Value* retrieveCombinedValue(const uint64_t startAddress,
                               const uint8_t byteCount, Value* orgLoad);

  void addValueReference(Value* value, const uint64_t address);

  isPaged isValuePaged(Value* address, Instruction* ctxI);

  void pagedCheck(Value* address, Instruction* ctxI);

  void loadMemoryOp(LoadInst* inst);

  void insertMemoryOp(StoreInst* inst);
  set<APInt, APIntComparator> computePossibleValues(Value* V,
                                                    const uint8_t Depth = 0);

  Value* extractBytes(Value* value, const uint8_t startOffset,
                      const uint8_t endOffset);
  // end analysis

  // folders
  Value* createSelectFolder(Value* C, Value* True, Value* False,
                            const Twine& Name = "");

  Value* createGEPFolder(Type* Type, Value* Address, Value* Base,
                         const Twine& Name = "");

  Value* createAddFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createSubFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createOrFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createXorFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createICMPFolder(CmpInst::Predicate P, Value* LHS, Value* RHS,
                          const Twine& Name = "");
  Value* createNotFolder(Value* LHS, const Twine& Name = "");
  Value* createMulFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createSDivFolder(Value* LHS, Value* RHS, const Twine& Name = "");
  Value* createUDivFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createSRemFolder(Value* LHS, Value* RHS, const Twine& Name = "");
  Value* createURemFolder(Value* LHS, Value* RHS, const Twine& Name = "");
  Value* createAShrFolder(Value* LHS, Value* RHS, const Twine& Name = "");
  Value* createAndFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createTruncFolder(Value* V, Type* DestTy, const Twine& Name = "");

  Value* createZExtFolder(Value* V, Type* DestTy, const Twine& Name = "");

  Value* createZExtOrTruncFolder(Value* V, Type* DestTy,
                                 const Twine& Name = "");

  Value* createSExtFolder(Value* V, Type* DestTy, const Twine& Name = "");

  Value* createSExtOrTruncFolder(Value* V, Type* DestTy,
                                 const Twine& Name = "");

  Value* createLShrFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createLShrFolder(Value* LHS, const uint64_t RHS,
                          const Twine& Name = "");

  Value* createLShrFolder(Value* LHS, const APInt RHS, const Twine& Name = "");

  Value* createShlFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createShlFolder(Value* LHS, const uint64_t RHS,
                         const Twine& Name = "");

  Value* createShlFolder(Value* LHS, const APInt RHS, const Twine& Name = "");
  Value* folderBinOps(Value* LHS, Value* RHS, const Twine& Name,
                      Instruction::BinaryOps opcode);
  Value* createInstruction(const unsigned opcode, Value* operand1,
                           Value* operand2, Type* destType, const Twine& Name);

  Value* getOrCreate(const InstructionKey& key, uint8_t opcode,
                     const Twine& Name);
  Value* doPatternMatching(Instruction::BinaryOps const I, Value* const op0,
                           Value* const op1);

  // end folders

  // semantics definition
  DEFINE_FUNCTION(movs_X);
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
  DEFINE_FUNCTION(popcnt);
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
  void lift_imul2(const bool isSigned);
  DEFINE_FUNCTION(imul);
  DEFINE_FUNCTION(mul);
  DEFINE_FUNCTION(div2);
  DEFINE_FUNCTION(div);
  DEFINE_FUNCTION(idiv2);
  DEFINE_FUNCTION(idiv);
  DEFINE_FUNCTION(xor);
  DEFINE_FUNCTION(or);
  DEFINE_FUNCTION(and);
  DEFINE_FUNCTION(andn);
  DEFINE_FUNCTION(rol);
  DEFINE_FUNCTION(ror);
  DEFINE_FUNCTION(inc);
  DEFINE_FUNCTION(dec);
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
  DEFINE_FUNCTION(pext);
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
  DEFINE_FUNCTION(lzcnt);
  DEFINE_FUNCTION(bzhi);
  DEFINE_FUNCTION(bsr);
  DEFINE_FUNCTION(bsf);
  DEFINE_FUNCTION(blsr);
  DEFINE_FUNCTION(tzcnt);
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
  DEFINE_FUNCTION(bextr);
  // end semantics definition
};
extern vector<lifterClass*> lifters;

#undef DEFINE_FUNCTION
#endif // LIFTERCLASS_H