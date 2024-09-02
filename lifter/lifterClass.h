#ifndef LIFTERCLASS_H
#define LIFTERCLASS_H
#include "FunctionSignatures.h"
#include "GEPTracker.h"
#include "includes.h"
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/DomConditionCache.h>
#include <memory>

#define DEFINE_FUNCTION(name) void lift_##name()

struct InstructionKey {
  unsigned opcode;
  bool cast;
  Value* operand1;
  union {
    Value* operand2;
    Type* destType;
  };

  InstructionKey(unsigned opcode, Value* operand1, Value* operand2)
      : opcode(opcode), cast(0), operand1(operand1), operand2(operand2){};

  InstructionKey(unsigned opcode, Value* operand1, Type* destType)
      : opcode(opcode), cast(1), operand1(operand1), destType(destType){};

  bool operator==(const InstructionKey& other) const {
    if (cast != other.cast)
      return false;
    if (cast) {
      return opcode == other.opcode && operand1 == other.operand1 &&
             destType == other.destType;
    } else {
      return opcode == other.opcode && operand1 == other.operand1 &&
             operand2 == other.operand2;
    }
  }
  struct InstructionKeyInfo {
    // Custom hash function
    static inline unsigned getHashValue(const InstructionKey& key) {
      auto h1 = llvm::hash_value(key.opcode);
      auto h2 = llvm::hash_value(key.operand1);
      auto h3 = key.cast ? llvm::hash_value(key.destType)
                         : llvm::hash_value(key.operand2);
      return llvm::hash_combine(h1, h2, h3);
    }

    // Equality function
    static inline bool isEqual(const InstructionKey& lhs,
                               const InstructionKey& rhs) {
      return lhs == rhs;
    }

    // Define empty and tombstone keys
    static inline InstructionKey getEmptyKey() {
      return InstructionKey(0, nullptr, static_cast<Value*>(nullptr));
    }

    static inline InstructionKey getTombstoneKey() {
      return InstructionKey(~0U, nullptr, static_cast<Value*>(nullptr));
    }
  };
};

class FlagManager {
public:
  std::unique_ptr<llvm::SmallVector<Value*, FLAGS_END>> vec;

  // Default Constructor
  FlagManager()
      : vec(std::make_unique<llvm::SmallVector<Value*, FLAGS_END>>()) {}

  // Copy Constructor
  FlagManager(const FlagManager& other)
      : vec(other.vec ? std::make_unique<llvm::SmallVector<Value*, FLAGS_END>>(
                            *other.vec)
                      : nullptr) {}

  // Copy Assignment
  FlagManager& operator=(const FlagManager& other) {
    if (this != &other) {
      vec = other.vec ? std::make_unique<llvm::SmallVector<Value*, FLAGS_END>>(
                            *other.vec)
                      : nullptr;
    }
    return *this;
  }

  // Move Constructor
  FlagManager(FlagManager&& other) noexcept = default;

  // Move Assignment
  FlagManager& operator=(FlagManager&& other) noexcept = default;

  // Destructor (automatically handled by unique_ptr)
  ~FlagManager() = default;

  // Overload the [] operator for getting register values

  int getFlagIndex(Flag key) const {

    // For ordered registers RAX to R15, map directly by offset from RAX
    return key;
  }

  llvm::Value*& operator[](Flag key) {
    int index = getFlagIndex(key);
    return (*vec)[index];
  }
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
  std::unique_ptr<llvm::SmallVector<Value*, REGISTER_COUNT>> vec;

  // Default Constructor
  RegisterManager()
      : vec(std::make_unique<llvm::SmallVector<Value*, REGISTER_COUNT>>()) {}

  // Copy Constructor
  RegisterManager(const RegisterManager& other)
      : vec(other.vec
                ? std::make_unique<llvm::SmallVector<Value*, REGISTER_COUNT>>(
                      *other.vec)
                : nullptr) {}

  // Copy Assignment
  RegisterManager& operator=(const RegisterManager& other) {
    if (this != &other) {
      vec = other.vec
                ? std::make_unique<llvm::SmallVector<Value*, REGISTER_COUNT>>(
                      *other.vec)
                : nullptr;
    }
    return *this;
  }

  // Move Constructor
  RegisterManager(RegisterManager&& other) noexcept = default;

  // Move Assignment
  RegisterManager& operator=(RegisterManager&& other) noexcept = default;

  // Destructor (automatically handled by unique_ptr)
  ~RegisterManager() = default;

  // Overload the [] operator for getting register values

  int getRegisterIndex(ZydisRegister key) const {

    if (key == ZYDIS_REGISTER_RIP) {
      return RIP_;
    }

    if (key == ZYDIS_REGISTER_RFLAGS) {
      return RFLAGS_;
    }

    // For ordered registers RAX to R15, map directly by offset from RAX
    return key - ZYDIS_REGISTER_RAX;
  }

  llvm::Value*& operator[](ZydisRegister key) {
    int index = getRegisterIndex(key);
    return (*vec)[index];
  }
};

struct BBInfo {
  uint64_t runtime_address;
  llvm::BasicBlock* block;
  RegisterManager registers;

  BBInfo(){};

  BBInfo(uint64_t runtime_address, llvm::BasicBlock* block,
         RegisterManager& registers)
      : runtime_address(runtime_address), block(block), registers(registers) {}
};

class lifterClass {
public:
  // unique
  IRBuilder<>& builder;
  BBInfo blockInfo;

  RegisterManager Registers;
  FlagManager FlagList;
  std::unique_ptr<DenseMap<Instruction*, APInt>> assumptions;
  std::unique_ptr<DenseMap<uint64_t, ValueByteReference*>> buffer;
  std::unique_ptr<
      DenseMap<InstructionKey, Value*, InstructionKey::InstructionKeyInfo>>
      cache;

  unsigned int instct = 0;
  SimplifyQuery* cachedquery;

  DominatorTree* DT;
  BasicBlock* lastBB = nullptr;
  map<uint64_t, uint64_t> pageMap;
  vector<Instruction*> memInfos;

  ZydisDisassembledInstruction* instruction = nullptr;

  // Constructor
  lifterClass(IRBuilder<>& irbuilder)
      : builder(irbuilder),
        assumptions(std::make_unique<DenseMap<Instruction*, APInt>>()),
        buffer(std::make_unique<DenseMap<uint64_t, ValueByteReference*>>()),
        cache(
            std::make_unique<DenseMap<InstructionKey, Value*,
                                      InstructionKey::InstructionKeyInfo>>()) {}

  // Copy Constructor
  lifterClass(const lifterClass& other)
      : builder(other.builder),
        assumptions(other.assumptions
                        ? std::make_unique<DenseMap<Instruction*, APInt>>(
                              *other.assumptions)
                        : nullptr),
        buffer(std::make_unique<DenseMap<uint64_t, ValueByteReference*>>()),
        cache(std::make_unique<DenseMap<InstructionKey, Value*,
                                        InstructionKey::InstructionKeyInfo>>(
            *other.cache)) {

    // Deep copy of buffer, including ValueByteReference objects
    for (const auto& [key, value] : *other.buffer) {
      if (value) {
        (*buffer)[key] =
            new ValueByteReference(*value); // Deep copy of ValueByteReference
      }
    }
  }

  // Move Constructor
  lifterClass(lifterClass&& other) noexcept = default;

  // Copy Assignment
  lifterClass& operator=(const lifterClass& other) {
    if (this != &other) {
      assumptions =
          std::make_unique<DenseMap<Instruction*, APInt>>(*other.assumptions);
      cache = std::make_unique<
          DenseMap<InstructionKey, Value*, InstructionKey::InstructionKeyInfo>>(
          *other.cache);
      // Deep copy of buffer, including ValueByteReference objects
      buffer = std::make_unique<DenseMap<uint64_t, ValueByteReference*>>();
      for (const auto& [key, value] : *other.buffer) {
        if (value) {
          (*buffer)[key] =
              new ValueByteReference(*value); // Deep copy of ValueByteReference
        }
      }
    }
    return *this;
  }

  // Move Assignment
  lifterClass& operator=(lifterClass&& other) noexcept = delete;

  // Destructor to handle manually allocated ValueByteReference objects
  ~lifterClass() {
    // Clean up manually allocated ValueByteReference objects in buffer
    if (buffer) {
      for (auto& [key, value] : *buffer) {
        delete value;
      }
    }
  }

  bool run = 0;      // we may set 0 so to trigger jumping to next basic block
  bool finished = 0; // finished, unfinished, unreachable
  bool isUnreachable = 0;

  // shared globals
  Value* memory;
  Value* TEB;
  Function* fnc;

  // we dont rely on this anymore? but fuck it, as long as they dont cause huge
  // overhead
  DomConditionCache* DC = new DomConditionCache();
  unsigned long BIlistsize = 0;
  vector<BranchInst*> BIlist;

  void liftInstruction();
  void liftInstructionSemantics();
  void branchHelper(Value* condition, string instname, int numbered,
                    bool reverse = false);

  // init
  void Init_Flags();
  void initDomTree(Function& F) { DT = new DominatorTree(F); }
  // end init

  // getters-setters
  Value* setFlag(Flag flag, Value* newValue = nullptr);
  Value* getFlag(Flag flag);
  RegisterManager& getRegisters();
  void setRegisters(RegisterManager newRegisters);
  void InitRegisters(Function* function, ZyanU64 rip);
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
  Value* GetRFLAGSValue();
  // end getters-setters
  // misc
  void callFunctionIR(string functionName,
                      funcsignatures::functioninfo* funcInfo);
  Value* GetEffectiveAddress(ZydisDecodedOperand& op, int possiblesize);
  vector<Value*> parseArgs(funcsignatures::functioninfo* funcInfo);
  FunctionType* parseArgsType(funcsignatures::functioninfo* funcInfo,
                              LLVMContext& context);

  Value* computeSignFlag(Value* value);
  Value* computeZeroFlag(Value* value);
  Value* computeParityFlag(Value* value);
  Value* computeAuxFlagSbb(Value* Lvalue, Value* Rvalue, Value* cf);
  Value* computeOverflowFlagSbb(Value* Lvalue, Value* Rvalue, Value* cf,
                                Value* sub);

  Value* computeOverflowFlagSub(Value* Lvalue, Value* Rvalue, Value* sub);
  Value* computeOverflowFlagAdd(Value* Lvalue, Value* Rvalue, Value* add);
  Value* computeOverflowFlagAdc(Value* Lvalue, Value* Rvalue, Value* cf,
                                Value* add);
  // end misc
  // analysis
  KnownBits analyzeValueKnownBits(Value* value, Instruction* ctxI);

  Value* solveLoad(LoadInst* load);

  SimplifyQuery createSimplifyQuery(Instruction* Inst);

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

  void markMemPaged(uint64_t start, uint64_t end) {
    //
    pageMap[start] = end;
  }

  bool isMemPaged(uint64_t address) {
    auto it = pageMap.upper_bound(address);
    if (it == pageMap.begin())
      return false;
    --it;
    return address >= it->first && address < it->second;
  }

  void updateMemoryOp(StoreInst* inst);

  void updateValueReference(Instruction* inst, Value* value, uint64_t address);

  Value* retrieveCombinedValue(uint64_t startAddress, uint64_t byteCount,
                               Value* orgLoad);

  void addValueReference(Instruction* inst, Value* value, uint64_t address);

  isPaged isValuePaged(Value* address, Instruction* ctxI);

  void pagedCheck(Value* address, Instruction* ctxI);

  void loadMemoryOp(LoadInst* inst);

  void insertMemoryOp(StoreInst* inst);
  set<APInt, APIntComparator> computePossibleValues(Value* V);

  Value* extractBytes(Value* value, uint64_t startOffset, uint64_t endOffset);
  // end analysis

  // folders
  Value* createSelectFolder(Value* C, Value* True, Value* False,
                            const Twine& Name = "");

  Value* createAddFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createSubFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createOrFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createXorFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createICMPFolder(CmpInst::Predicate P, Value* LHS, Value* RHS,
                          const Twine& Name = "");

  Value* createAndFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createTruncFolder(Value* V, Type* DestTy, const Twine& Name = "");

  Value* createZExtFolder(Value* V, Type* DestTy, const Twine& Name = "");

  Value* createZExtOrTruncFolder(Value* V, Type* DestTy,
                                 const Twine& Name = "");

  Value* createSExtFolder(Value* V, Type* DestTy, const Twine& Name = "");

  Value* createSExtOrTruncFolder(Value* V, Type* DestTy,
                                 const Twine& Name = "");

  Value* createLShrFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createLShrFolder(Value* LHS, uint64_t RHS, const Twine& Name = "");

  Value* createLShrFolder(Value* LHS, APInt RHS, const Twine& Name = "");

  Value* createShlFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createShlFolder(Value* LHS, uint64_t RHS, const Twine& Name = "");

  Value* createShlFolder(Value* LHS, APInt RHS, const Twine& Name = "");
  Value* folderBinOps(Value* LHS, Value* RHS, const Twine& Name,
                      Instruction::BinaryOps opcode);
  Value* createInstruction(unsigned opcode, Value* operand1, Value* operand2,
                           Type* destType, const Twine& Name);

  Value* getOrCreate(const InstructionKey& key, const Twine& Name);
  Value* doPatternMatching(Instruction::BinaryOps const I, Value* const op0,
                           Value* const op1);

  // end folders

  // semantics definition
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
  // end semantics definition
};
extern vector<lifterClass*> lifters;
#endif // LIFTERCLASS_H