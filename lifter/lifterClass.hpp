#ifndef LIFTERCLASS_H
#define LIFTERCLASS_H
#include "CommonDisassembler.hpp"
#include "FunctionSignatures.hpp"
#include "GEPTracker.h"
#include "PathSolver.h"
#include "ZydisDisassembler.hpp"
#include "ZydisDisassembler_mnemonics.h"
#include "ZydisDisassembler_registers.h"
#include "fileReader.hpp"
#include "icedDisassembler.hpp"
#include "icedDisassembler_mnemonics.h"
#include "icedDisassembler_registers.h"
#include "includes.h"
#include "utils.h"
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/DomConditionCache.h>
#include <llvm/Analysis/InstSimplifyFolder.h>
#include <llvm/Analysis/SimplifyQuery.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/KnownBits.h>
#include <set>
#include <utility>

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
      return llvm::hash_combine(key.operand1, key.operand2);
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
    opcodeCaches[opcode][key] = value;
  }

  Value* lookup(uint8_t opcode, const InstructionKey& key) const {
    const auto& cache = opcodeCaches[opcode];
    auto it = cache.find(key);
    return it != cache.end() ? it->second : nullptr;
  }

private:
  using CacheMap = llvm::SmallDenseMap<InstructionKey, Value*, 4,
                                       InstructionKey::InstructionKeyInfo>;
  std::array<CacheMap, 256> opcodeCaches; // this should be faster
};

class floatingPointValue {
public:
  Value* v1;
  Value* v2;
};

template <Registers Register> class RegisterManager {
public:
  enum RegisterIndex {
    RAX_ = 0,
    RCX_ = 1,
    RDX_ = 2,
    RBX_ = 3,
    RSP_ = 4,
    RBP_ = 5,
    RSI_ = 6,
    RDI_ = 7,
    R8_ = 8,
    R9_ = 9,
    R10_ = 10,
    R11_ = 11,
    R12_ = 12,
    R13_ = 13,
    R14_ = 14,
    R15_ = 15,
    RIP_ = 16,
    RFLAGS_ = 17,
    REGISTER_COUNT = RFLAGS_ // Total number of registers
  };
  std::array<Value*, REGISTER_COUNT> vec;

  RegisterManager() {}
  RegisterManager(const RegisterManager& other) : vec(other.vec) {}

  // Overload the [] operator for getting register values

  int getRegisterIndex(Register key) const {

    switch (key) {
    case Register::RIP: {
      return RIP_;
    }
    case Register::RFLAGS: {
      return RFLAGS_;
    }
    default: {
      // For ordered registers RAX to R15, map directly by offset from RAX

      /*
      if (!(key >= Register::RAX && key <= Register::R15)) {
        printvalueforce2("debug this"); // debug this branch l8r
      }
      */
      assert(key >= Register::RAX && key <= Register::R15 &&
             "Key must be between RAX and R15");

      return (static_cast<int>(key) - static_cast<int>(Register::RAX));
    }
    }
  }

  llvm::Value*& operator[](Register key) {
    int index = getRegisterIndex(key);
    return vec[index];
  }
};

/*
struct simpleFPV {
  Value* v1;
  Value* v2;
};
class RegisterManagerFP {
public:
  enum RegisterIndexFP {
    XMM0_ = 0,
    XMM1_,
    XMM2_,
    XMM3_,
    XMM4_,
    XMM5_,
    XMM6_,
    XMM7_,
    XMM8_,
    XMM9_,
    XMM10_,
    XMM11_,
    XMM12_,
    XMM13_,
    XMM14_,
    XMM15_,
    REGISTER_COUNT // Total number of registers
  };
  std::array<simpleFPV, REGISTER_COUNT> vec;

  RegisterManagerFP() {}
  RegisterManagerFP(const RegisterManagerFP& other) : vec(other.vec) {}

  // Overload the [] operator for getting register values

  int getRegisterIndex( Register key) const {
    return key - Register::XMM0;
  }

  simpleFPV& operator[](Register key) {
    int index = getRegisterIndex(key);
    printvalue2(index);
    return vec[index];
  }
};
*/

struct BBInfo {
  uint64_t block_address;
  llvm::BasicBlock* block;

  BBInfo(){};

  BBInfo(uint64_t runtime_address, llvm::BasicBlock* block)
      : block_address(runtime_address), block(block) {}

  // bool operator==(const BBInfo& other) const {
  //   if (block_address != other.block_address)
  //     return false;
  //   return block == other.block;
  // }

  // struct BBInfoKeyInfo {
  //   // Custom hash function
  //   static inline unsigned getHashValue(const BBInfo& key) {
  //     return llvm::hash_combine(key.block_address, key.block);
  //   }

  //   // Equality function
  //   static inline bool isEqual(const BBInfo& lhs, const BBInfo& rhs) {
  //     return lhs == rhs;
  //   }

  //   // Define empty and tombstone keys
  //   static inline BBInfo getEmptyKey() {
  //     return BBInfo(-1, static_cast<BasicBlock*>(nullptr));
  //   }

  //   static inline BBInfo getTombstoneKey() {
  //     return BBInfo(0, static_cast<BasicBlock*>(nullptr));
  //   }
  // };
};

class LazyValue {
public:
  using ComputeFunc = std::function<llvm::Value*()>;

  mutable std::optional<llvm::Value*> value;

  ComputeFunc computeFunc;

  LazyValue() : value(nullptr) {}
  LazyValue(llvm::Value* val) : value(val) {}
  LazyValue(std::function<llvm::Value*()> calc)
      : computeFunc(calc), value(std::nullopt) {}

  // get value, calculate if doesnt exist
  llvm::Value* get() const {
    if (!value.has_value() && computeFunc) {

      value = (computeFunc)();
    }

    return value.value_or(nullptr);
  }

  // Set a new value directly, bypassing lazy evaluation
  void set(llvm::Value* newValue) {
    value = newValue;
    computeFunc = nullptr;
  }
  void setCalculation(const std::function<llvm::Value*()> calc) {
    computeFunc = calc;
    value = std::nullopt; // Reset the stored value
  }
};

#define MERGEN_LIFTER_DEFINITION_TEMPLATES(ret)                                \
  template <Mnemonics Mnemonic, Registers Register,                            \
            template <typename, typename> class DisassemblerBase>              \
    requires Disassembler<DisassemblerBase<Mnemonic, Register>, Mnemonic,      \
                          Register>                                            \
  ret lifterClass<Mnemonic, Register, DisassemblerBase>

// main lifter
#ifdef ICED_FOUND
template <Mnemonics Mnemonic = Mergen::IcedMnemonics,
          Registers Register = Mergen::IcedRegister,
          template <typename, typename> class DisassemblerBase =
              Mergen::icedDisassembler>
#else
template <Mnemonics Mnemonic = Mergen::ZydisMnemonic,
          Registers Register = Mergen::ZydisRegister,
          template <typename, typename> class DisassemblerBase =
              Mergen::ZydisDisassembler>
#endif
  requires Disassembler<DisassemblerBase<Mnemonic, Register>, Mnemonic,
                        Register>
class lifterClass {
public:
  using Disassembler = DisassemblerBase<Mnemonic, Register>;

  llvm::IRBuilder<llvm::InstSimplifyFolder>& builder;
  BBInfo blockInfo;
  uint64_t current_address;
  bool run = 0;      // we may set 0 so to trigger jumping to next basic block
  bool finished = 0; // finished, unfinished, unreachable
  bool isUnreachable = 0;
  uint32_t counter = 0;
  // unique

  funcsignatures<Register> signatures;
  MergenDisassembledInstruction_base<Mnemonic, Register> instruction;

  Disassembler dis;

  void runDisassembler(void* buffer, size_t size = 15) {
    instruction = dis.disassemble(buffer, size);
  }

  // handle the file here
  uint8_t* fileBase;

  // lifts single instruction
  void liftBytes(void* bytes, size_t size = 15) {
    // what about the basicblock?
    runDisassembler(bytes, size);
    current_address += instruction.length;
    liftInstructionSemantics();
    this->counter++;
  };

  x86_64FileReader file;

  void loadFile(uint8_t* file_start) {
    fileBase = file_start;
    file = x86_64FileReader(file_start);
  }

  // also lifts single inst
  void liftAddress(uint64_t addr, size_t size = 15) {
    file.filebase_exists();

    this->current_address = addr;
    auto offset = file.address_to_mapped_address(addr);
    // what about the basicblock?
    printvalue2(offset);
    printvalue2(*(uint8_t*)offset);
    runDisassembler((void*)offset, size);
    const auto ct = (llvm::format_hex_no_prefix(this->counter, 0));
    const auto runtime_address =
        (llvm::format_hex_no_prefix(this->current_address, 0));
    printvalue2(ct);
    printvalue2(runtime_address);
#ifndef _NODEV
    debugging::doIfDebug([&]() { printvalue2(this->instruction.text); });
#endif
    // also pass the file to address_to_mapped_address?
    this->current_address += instruction.length;
    liftInstruction();
    this->counter++;
  };

  void liftBasicBlockFromBytes(std::vector<uint8_t> bytes) {
    //
  }

  // refactor: put these stuff in a class (?) so we can properly have a fully
  // symbolized version
  struct backup_point {
    RegisterManager<Register> regs;
    llvm::DenseMap<uint64_t, ValueByteReference> buffer;

    bool operator==(const backup_point& other) const {
      if (buffer != other.buffer)
        return false;
      return regs == other.regs;
    }
    backup_point(){};

    backup_point(backup_point& other)
        : regs(other.regs), buffer(other.buffer){};

    backup_point(backup_point&& other)
        : regs(other.regs), buffer(other.buffer){};

    backup_point(RegisterManager<Register> registers,
                 llvm::DenseMap<uint64_t, ValueByteReference> map)
        : regs(registers), buffer(map){};

    backup_point& operator=(const backup_point&) = default;
  };
  llvm::DenseMap<BasicBlock*, backup_point> BBbackup;
  void branch_backup(BasicBlock* bb) {
    //
    BBbackup[bb] = {Registers, buffer};
  }

  void load_backup(BasicBlock* bb) {
    if (BBbackup.contains(bb)) {
      auto bbinfo = BBbackup[bb];
      Registers = bbinfo.regs;
      buffer = bbinfo.buffer;
    }
  }

  void liftBasicBlockFromAddress(uint64_t addr) {
    printvalue2(this->finished);
    printvalue2(this->run);
    this->run = 1;
    while (this->finished == 0 && this->run) {
      // TODO: refactor logic for finished and run, instead semantics should
      // return the info about jumps
      liftAddress(addr);
      addr = current_address;
    }
  }

  bool getUnvisitedAddr(BBInfo& out) {
    if (unvisitedBlocks.empty())
      return false;
    out = std::move(unvisitedBlocks.back());
    unvisitedBlocks.pop_back();
    return true;
  }

  void writeFunctionToFile(const std::string filename) {

    std::error_code EC_noopt;
    llvm::raw_fd_ostream OS_noopt(filename, EC_noopt);
    fnc->print(OS_noopt, nullptr);
  }

  // ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions;
  llvm::DenseMap<uint64_t, ValueByteReference> buffer;
  using flagManager = std::array<LazyValue, FLAGS_END>;
  // llvm::DenseMap<Value*, flagManager> flagbuffer;

  flagManager FlagList;
  RegisterManager<Register> Registers;
  // RegisterManagerFP RegistersFP;

  llvm::DomConditionCache* DC = new llvm::DomConditionCache();

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
        return llvm::hash_combine(key.addr, key.type + key.TEB);
      }

      // Equality function
      static inline bool isEqual(const GEPinfo& lhs, const GEPinfo& rhs) {
        return lhs == rhs;
      }

      // Define empty and tombstone keys
      static inline GEPinfo getEmptyKey() { return GEPinfo(nullptr, 0, 0); }

      static inline GEPinfo getTombstoneKey() {
        return GEPinfo(nullptr, -1, -1);
      }
    };
  };
  llvm::DenseMap<GEPinfo, Value*, typename GEPinfo::GEPinfoKeyInfo> GEPcache;
  std::vector<llvm::Instruction*> memInfos;

  // todo : std::set
  std::vector<BBInfo> unvisitedBlocks;
  std::vector<BBInfo> visitedBlocks;

  // global
  llvm::Value* memoryAlloc;
  llvm::Function* fnc;

  lifterClass(llvm::IRBuilder<llvm::InstSimplifyFolder>& irbuilder,
              uint64_t runtime_addr = 0)
      : builder(irbuilder) {

    InitRegisters(irbuilder.GetInsertBlock()->getParent(), runtime_addr);
  };

  lifterClass(llvm::IRBuilder<llvm::InstSimplifyFolder>& irbuilder,
              uint8_t* fileBase, uint64_t runtime_addr = 0)
      : builder(irbuilder), file(fileBase), fileBase(fileBase) {

    InitRegisters(irbuilder.GetInsertBlock()->getParent(), runtime_addr);
  };

  lifterClass(const lifterClass& other)
      : builder(other.builder), // Reference copied directly
        blockInfo(
            other.blockInfo), // Assuming BBInfo has a proper copy constructor
        fileBase(other.fileBase), run(other.run), finished(0),
        counter(other.counter), isUnreachable(other.isUnreachable),
        instruction(other.instruction), // Shallow copy of the pointer
        assumptions(other.assumptions), // Deep copy of assumptions
        buffer(other.buffer), file(other.file),
        FlagList(other.FlagList), // Deep copy handled by unordered_map's copy
                                  // constructor
        // RegistersFP(other.RegistersFP), // Assuming RegisterManager has a
        // copy constructor
        Registers(other.Registers), // Assuming RegisterManager has a copy
                                    // constructor
        DC(other.DC),               // Deep copy of DC
        instct(other.instct),
        cachedquery(other.cachedquery), // Assuming raw pointer, copied directly
        DT(other.DT),                   // Assuming pointer, copied directly
        lastBB(other.lastBB), BIlistsize(other.BIlistsize),
        pageMap(other.pageMap), // Deep copy handled by map's copy constructor
        BIlist(other.BIlist), // Deep copy handled by vector's copy constructor
        cache(other.cache), // Deep copy handled by DenseMap's copy constructor
        memInfos(
            other.memInfos), // Deep copy handled by vector's copy constructor
        memoryAlloc(other.memoryAlloc), // Shallow copy of the pointer
        fnc(other.fnc) {}

  void liftInstruction();
  void liftInstructionSemantics();
  void branchHelper(llvm::Value* condition, const std::string& instname,
                    const int numbered, const bool reverse = false);

  // init
  void Init_Flags();
  void initDomTree(llvm::Function& F) { DT = new llvm::DominatorTree(F); }
  // end init

  std::optional<llvm::Value*> evaluateLLVMExpression(llvm::Value* value);

  // getters-setters
  llvm::Value* setFlag(const Flag flag, llvm::Value* newValue = nullptr);
  void setFlagUndef(const Flag flag) {
    auto undef = UndefValue::get(builder.getInt1Ty());
    FlagList[flag].set(undef); // Set the new value directly
  }

  void setFlag(const Flag flag, std::function<llvm::Value*()> calculation);
  LazyValue getLazyFlag(const Flag flag);
  llvm::Value* getFlag(const Flag flag);
  void InitRegisters(llvm::Function* function, uint64_t rip);
  llvm::Value* GetValueFromHighByteRegister(Register reg);
  llvm::Value* GetRegisterValue(const Register key);
  llvm::Value* GetMemoryValue(llvm::Value* address, uint8_t size);
  llvm::Value* SetValueToHighByteRegister(const Register reg,
                                          llvm::Value* value);
  llvm::Value* SetValueToSubRegister_8b(const Register reg, llvm::Value* value);
  llvm::Value* SetValueToSubRegister_16b(const Register reg,
                                         llvm::Value* value);

  // this actually might be a good reason for static polymorphism, since
  // current implementation cant be encapsulated in a class very efficently
  void createMemcpy(llvm::Value* src, llvm::Value* dest, llvm::Value* size);

  void SetRegisterValue(const Register key, llvm::Value* value);
  void SetMemoryValue(llvm::Value* address, llvm::Value* value);
  void SetRFLAGSValue(llvm::Value* value);
  PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                      llvm::Value* simplifyValue);
  llvm::Value* popStack(int size);
  void pushFlags(const std::vector<llvm::Value*>& value,
                 const std::string& address);
  std::vector<llvm::Value*> GetRFLAGS();

  /*
  simpleFPV GetOperandValueFP(const ZydisDecodedOperand& op,
                              const std::string& address = "");
  simpleFPV SetOperandValueFP(const ZydisDecodedOperand& op, simpleFPV value,
                              const std::string& address = "");
  */

  Register GetAccumulatorRegister(uint8_t size = 64) {
    switch (size) {
    case 64:
      return Register::RAX;
    case 32:
      return Register::EAX;
    case 16:
      return Register::AX;
    case 8:
      return Register::AL;
    default:
      UNREACHABLE("invalid acc");
    }
  }

  llvm::Value* GetIndexValue(uint8_t index);

  void SetIndexValue(uint8_t index, Value* value);
  /*
    llvm::Value* GetOperandValue(const ZydisDecodedOperand& op,
                                 const int possiblesize,
                                 const std::string& address = "");
    llvm::Value* SetOperandValue(const ZydisDecodedOperand& op,
                                 llvm::Value* value,
                                 const std::string& address = "");
                                 */
  llvm::Value* GetRFLAGSValue();

  llvm::Value* getSPaddress() { return GetRegisterValue(Register::RSP); }
  llvm::Value* getSP() { return getPointer(getSPaddress()); };
  // end getters-setters
  // misc
  llvm::Value* callFunctionIR(const std::string& functionName,
                              funcsignatures<Register>::functioninfo* funcInfo);
  llvm::Value* GetEffectiveAddress();
  llvm::Value* getPointer(llvm::Value* value);

  std::vector<llvm::Value*>
  parseArgs(funcsignatures<Register>::functioninfo* funcInfo);
  llvm::FunctionType*
  parseArgsType(funcsignatures<Register>::functioninfo* funcInfo,
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

  llvm::Value* solveLoad(LazyValue load, Value* ptr, uint8_t size);

  llvm::SimplifyQuery createSimplifyQuery(Instruction* Inst);

  void RegisterBranch(llvm::BranchInst* BI) {
    //
    BIlist.push_back(BI);
  }

  llvm::DominatorTree* getDomTree() { return DT; }

  void updateDomTree(llvm::Function& F) {
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

    auto rs = address >= it->first && address < it->second;
    return rs;
  }

  std::set<llvm::APInt, APIntComparator>
  getPossibleValues(const llvm::KnownBits& known, unsigned max_unknown);

  Value* retrieveCombinedValue(const uint64_t startAddress,
                               const uint8_t byteCount, LazyValue orgLoad);

  void addValueReference(Value* value, const uint64_t address);

  isPaged isValuePaged(Value* address, Instruction* ctxI);

  void pagedCheck(Value* address, Instruction* ctxI);

  void loadMemoryOp(Value* inst);

  void insertMemoryOp(llvm::StoreInst* inst);
  std::set<llvm::APInt, APIntComparator>
  computePossibleValues(Value* V, const uint8_t Depth = 0);

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

  Value* createICMPFolder(llvm::CmpInst::Predicate P, Value* LHS, Value* RHS,
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

  Value* createLShrFolder(Value* LHS, const llvm::APInt RHS,
                          const Twine& Name = "");

  Value* createShlFolder(Value* LHS, Value* RHS, const Twine& Name = "");

  Value* createShlFolder(Value* LHS, const uint64_t RHS,
                         const Twine& Name = "");

  Value* createShlFolder(Value* LHS, const llvm::APInt RHS,
                         const Twine& Name = "");
  Value* folderBinOps(Value* LHS, Value* RHS, const Twine& Name,
                      Instruction::BinaryOps opcode);
  Value* createInstruction(const unsigned opcode, Value* operand1,
                           Value* operand2, Type* destType, const Twine& Name);

  Value* getOrCreate(const InstructionKey& key, uint8_t opcode,
                     const Twine& Name);
  Value* doPatternMatching(Instruction::BinaryOps const I, Value* const op0,
                           Value* const op1);

  // end folders

  // would look nicer if we didnt have this, and do everything in a macro
  // instead?
  DEFINE_FUNCTION(movs_X);
  DEFINE_FUNCTION(movaps);
  DEFINE_FUNCTION(mov);

  DEFINE_FUNCTION(cmovcc);
  /*
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
  */
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

  DEFINE_FUNCTION(leave);

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
  DEFINE_FUNCTION(blsmsk);
  DEFINE_FUNCTION(pdep);
  DEFINE_FUNCTION(blsi);
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

  // sse
  /*
  DEFINE_FUNCTION(movdqa);
  DEFINE_FUNCTION(pand);
  DEFINE_FUNCTION(por);
  DEFINE_FUNCTION(pxor);
  DEFINE_FUNCTION(xorps);
  */
  // end semantics definition
};

extern std::vector<lifterClass<>*> lifters;

#undef DEFINE_FUNCTION
#endif // LIFTERCLASS_H