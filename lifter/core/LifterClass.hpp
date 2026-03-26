#ifndef LIFTERCLASSBASE_H
#define LIFTERCLASSBASE_H
#include "CommonDisassembler.hpp"
#include "AbiCallContract.hpp"
#include "FunctionSignatures.hpp"
#include "GEPTracker.h"
#include "InlinePolicy.hpp"
#include "PathSolver.h"
#include "RegisterManager.hpp"
#include "ZydisDisassembler.hpp"
#include "ZydisDisassemblerMnemonics.h"
#include "ZydisDisassemblerRegisters.h"
#include "FileReader.hpp"
#include "IcedDisassembler.hpp"
#include "IcedDisassemblerMnemonics.h"
#include "IcedDisassemblerRegisters.h"
#include "Includes.h"
#include "Utils.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/TargetTransformInfo.h"

#include <concepts>
#include <llvm/ADT/DenseMap.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/DomConditionCache.h>
#include <llvm/Analysis/DomTreeUpdater.h>
#include <llvm/Analysis/InstSimplifyFolder.h>
#include <llvm/Analysis/MemorySSAUpdater.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/SimplifyQuery.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/Support/KnownBits.h>
#include <memory>
#include <set>
#include <type_traits>
#include <utility>

using namespace llvm;

#ifndef DEFINE_FUNCTION
#define DEFINE_FUNCTION(name) void lift_##name()
#endif

enum class ControlFlow {
  Basic,
  Unflatten,
};

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

    // Define empty and tombstone keys — MUST be distinct for DenseMap.
    static inline InstructionKey getEmptyKey() {
      return InstructionKey(
          reinterpret_cast<Value*>(static_cast<uintptr_t>(-1)),
          reinterpret_cast<Value*>(static_cast<uintptr_t>(-1)));
    }

    static inline InstructionKey getTombstoneKey() {
      return InstructionKey(
          reinterpret_cast<Value*>(static_cast<uintptr_t>(-2)),
          reinterpret_cast<Value*>(static_cast<uintptr_t>(-2)));
    }
  };
};

class InstructionCache {
private:
  using CacheMap = llvm::SmallDenseMap<InstructionKey, Value*, 4,
                                       InstructionKey::InstructionKeyInfo>;

  std::array<CacheMap, 100> opcodeCaches;

public:
  void insert(uint8_t opcode, const InstructionKey& key, Value* value) {
    // Insert the key-value pair into the cache for the given opcode
    opcodeCaches[opcode][key] = value;
  }

  Value* lookup(uint8_t opcode, const InstructionKey& key) const {
    const auto& cache = opcodeCaches[opcode];
    auto it = cache.find(key);
    return it != cache.end() ? it->second : nullptr;
  }
  InstructionCache() = default;
  InstructionCache(InstructionCache& other) {
    for (size_t i = 0; i < opcodeCaches.size(); ++i) {
      opcodeCaches[i].reserve(other.opcodeCaches[i].size());
      for (auto& kv : other.opcodeCaches[i]) {
        opcodeCaches[i].try_emplace(kv.first, kv.second);
      }
    }
  };
  InstructionCache(const InstructionCache& other) {
    // we want to copy each SmallDenseMap individually
    for (size_t i = 0; i < opcodeCaches.size(); ++i) {
      // reserve because its faster
      opcodeCaches[i].reserve(other.opcodeCaches[i].size());
      for (auto& kv : other.opcodeCaches[i]) {
        opcodeCaches[i].try_emplace(kv.first, kv.second);
      }
    }
  }
  InstructionCache& operator=(const InstructionCache& other) {
    if (this == &other)
      return *this;
    for (size_t i = 0; i < opcodeCaches.size(); ++i) {
      opcodeCaches[i].clear();
      opcodeCaches[i].reserve(other.opcodeCaches[i].size());
      for (auto& kv : other.opcodeCaches[i]) {
        opcodeCaches[i].try_emplace(kv.first, kv.second);
      }
    }
    return *this;
  }
  InstructionCache(InstructionCache&&) = default;
  InstructionCache& operator=(InstructionCache&&) = default;
};


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
      : value(std::nullopt), computeFunc(calc) {}

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

template <typename T, typename R>
concept lifterConcept = Registers<R> && requires(T t) {
  { t.GetRegisterValue_impl(std::declval<R>()) } -> std::same_as<llvm::Value*>;
  {
    t.SetRegisterValue_impl(std::declval<R>(), std::declval<llvm::Value*>())
  } -> std::same_as<void>;
  {
    t.branch_backup_impl(std::declval<llvm::BasicBlock*>())
  } -> std::same_as<void>;
  {
    t.branch_backup_impl(std::declval<llvm::BasicBlock*>())
  } -> std::same_as<void>;
};

#define MERGEN_LIFTER_DEFINITION_TEMPLATES(ret)                                \
  template <typename Derived, Mnemonics Mnemonic, Registers Register,          \
            template <typename, typename> class DisassemblerBase>              \
    requires Disassembler<DisassemblerBase<Mnemonic, Register>, Mnemonic,      \
                          Register>                                            \
  ret lifterClassBase<Derived, Mnemonic, Register, DisassemblerBase>

struct LiftStats {
  unsigned blocks_attempted = 0;
  unsigned blocks_completed = 0;
  unsigned blocks_unreachable = 0;
  unsigned instructions_lifted = 0;
  unsigned instructions_unsupported = 0;
};

// main lifter
template <typename Derived = void,
#ifdef ICED_FOUND
          Mnemonics Mnemonic = Mergen::IcedMnemonics,
          Registers Register = Mergen::IcedRegister,
          template <typename, typename> class DisassemblerBase =
              Mergen::icedDisassembler
#else
          Mnemonics Mnemonic = Mergen::ZydisMnemonic,
          Registers Register = Mergen::ZydisRegister,
          template <typename, typename> class DisassemblerBase =
              Mergen::ZydisDisassembler
#endif
          >
  requires Disassembler<DisassemblerBase<Mnemonic, Register>, Mnemonic,
                        Register>
class lifterClassBase {
public:
  using Disassembler = DisassemblerBase<Mnemonic, Register>;

  std::unique_ptr<llvm::IRBuilder<llvm::InstSimplifyFolder>> builder;
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
  MemoryPolicy memoryPolicy;
  uint64_t stackReserve = 0x1000; // clamped reserve, set by configureDefaultMemoryPolicy
  FunctionInlinePolicy inlinePolicy;

  // ABI call-boundary configuration.
  // Strict: clobber volatile regs after non-inlineable calls (ABI-correct).
  // Compat: preserve all registers (legacy behavior, for diagnostics only).
  CallModelMode callModelMode = CallModelMode::Strict;
  AbiKind       defaultAbi    = AbiKind::Unknown; // auto-detected from arch mode

  // Returns the effective ABI for this binary. If defaultAbi is Unknown,
  // infers from file mode.
  AbiKind getEffectiveAbi() {
    if (defaultAbi != AbiKind::Unknown) return defaultAbi;
    return (file.getMode() == arch_mode::X64) ? AbiKind::X64_MSVC
                                                : AbiKind::X86_CDECL;
  }

  // Build CallEffects for an unknown call target using current config.
  CallEffects<Register> buildUnknownCallFx() {
    return abi::buildUnknownCallEffects<Register>(getEffectiveAbi(),
                                                  callModelMode);
  }

  // Import thunk detection for auto-outline policy.
  // Detects `jmp [rip+disp32]` (FF 25) thunks that read from the IAT.
  // Returns true if targetVA is an import thunk that should be outlined.
  bool isImportThunk(uint64_t targetVA) {
    // Read the first 6 bytes at the target address.
    uint64_t mapped = file.address_to_mapped_address(targetVA);
    if (mapped == 0) return false;
    auto* bytes = reinterpret_cast<const uint8_t*>(mapped);

    // Check for `jmp [rip+disp32]` = FF 25 xx xx xx xx
    if (bytes[0] != 0xFF || bytes[1] != 0x25) return false;

    // Decode RIP-relative displacement (next instruction is target + 6).
    int32_t disp;
    std::memcpy(&disp, bytes + 2, 4);
    uint64_t iatSlot = targetVA + 6 + disp;

    // Verify the IAT slot points outside the binary by reading its value.
    uint64_t importAddr = 0;
    if (!file.readMemory(iatSlot, 8, importAddr)) return false;

    // If the target address is not mapped in the PE, it's an external import.
    uint64_t externalMapped = file.address_to_mapped_address(importAddr);
    return externalMapped == 0;
  }

  // Import name resolution map: IAT slot VA -> import function name.
  // Built from PE import directory at setup. Used to emit named
  // function declarations instead of opaque inttoptr calls.
  std::unordered_map<uint64_t, std::string> importMap;

  // If targetVA is an import thunk, returns the import name.
  // Otherwise returns empty string.
  std::string resolveImportName(uint64_t targetVA) {
    uint64_t mapped = file.address_to_mapped_address(targetVA);
    if (mapped == 0) return {};
    auto* bytes = reinterpret_cast<const uint8_t*>(mapped);
    if (bytes[0] != 0xFF || bytes[1] != 0x25) return {};

    int32_t disp;
    std::memcpy(&disp, bytes + 2, 4);
    uint64_t iatSlot = targetVA + 6 + disp;

    auto it = importMap.find(iatSlot);
    if (it != importMap.end()) return it->second;
    return {};
  }

  // Returns true if the target should be outlined instead of inlined.
  bool shouldOutlineCall(uint64_t targetVA) {
    return isImportThunk(targetVA);
  }

  // ── Speculative call inlining with rollback ──────────────────────
  //
  // When the lifter encounters a `call` to a constant in-binary target,
  // it tries to inline the callee (Unflatten path). But if the callee
  // is too complex (statically-linked library, deep STL code), inlining
  // explodes. Speculative inlining sets a budget: if the callee exceeds
  // it, the lifter bails out and emits CreateCall + ABI effects instead.
  //
  // The return continuation BB is pre-created with a backup of the
  // pre-call state. On bail-out, the worklist resumes from that BB.

  struct SpeculativeCallInfo {
    bool     active         = false;
    uint64_t returnAddr     = 0;      // instruction after the call
    size_t   worklistFloor  = 0;      // worklist size before inlining
    bool     bailedOut      = false;   // set when budget exhausted
  };
  SpeculativeCallInfo speculativeCall;
  uint32_t speculativeCallBudget    = 0;   // instructions remaining (0 = inactive)
  uint32_t maxCallInlineBudget      = 0;   // 0 = disabled (no speculative limit)

  void runDisassembler(const void* buffer, size_t size = 15) {

    instruction = dis.disassemble(buffer, size);
  }

  // handle the file here
  uint8_t* fileBase;

  // lifts single instruction
  void liftBytes(const void* bytes, size_t size = 15) {
    // what about the basicblock?
    this->hadConditionalBranch = false;
    this->lastConditionalBranchResolved = false;
    this->lastBranchTaken = false;
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
    this->hadConditionalBranch = false;
    this->lastConditionalBranchResolved = false;
    this->lastBranchTaken = false;

    this->current_address = addr;
    auto offset = file.address_to_mapped_address(addr);
    if (offset == 0) {
      this->run = 0;
      this->finished = 1;
      builder->CreateUnreachable();
      return;
    }
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

  // useless in symbolic?
  void branch_backup(BasicBlock* bb) {
    static_cast<Derived*>(this)->branch_backup_impl(bb);
  }
  // useless in symbolic?
  void load_backup(BasicBlock* bb) {
    static_cast<Derived*>(this)->load_backup_impl(bb);
  }

  void liftBasicBlockFromAddress(uint64_t addr) {
    ++liftStats.blocks_attempted;
    printvalue2(this->finished);
    printvalue2(this->run);
    this->run = 1;
    while (this->finished == 0 && this->run) {
      // Speculative call budget check: bail if callee is too complex.
      if (speculativeCall.active && speculativeCallBudget > 0) {
        speculativeCallBudget--;
        if (speculativeCallBudget == 0) {
          // Budget exhausted — abandon speculative inline.
          if (!builder->GetInsertBlock()->getTerminator()) {
            builder->CreateUnreachable();
          }
          run = 0;
          speculativeCall.bailedOut = true;
          speculativeCall.active = false;

          // Trim worklist: remove all callee blocks pushed since the call.
          unvisitedBlocks.resize(speculativeCall.worklistFloor);

          // Push the return continuation BB onto the worklist.
          auto it = addrToBB.find(speculativeCall.returnAddr);
          if (it != addrToBB.end()) {
            BBInfo retInfo(speculativeCall.returnAddr, it->second);
            unvisitedBlocks.push_back(retInfo);
          }

          std::cout << "[call-abi] speculative inline bail-out at 0x"
                    << std::hex << (addr) << std::dec
                    << ", resuming at 0x" << std::hex
                    << speculativeCall.returnAddr << std::dec
                    << "\n" << std::flush;
          return;
        }
      }

      auto currentblock = builder->GetInsertBlock()->getName();
      printvalue2(currentblock);
      liftAddress(addr);
      ++liftStats.instructions_lifted;
      addr = current_address;
    }
    if (this->finished)
      ++liftStats.blocks_completed;
  }

  bool addUnvisitedAddr(BBInfo& bb) {
    printvalue2(bb.block_address);
    printvalue2("added");
    unvisitedBlocks.push_back(bb);
    return true;
  }

  /*
  filter : filter for empty blocks
  */
  bool getUnvisitedAddr(BBInfo& out, bool filter = 0) {
    while (!unvisitedBlocks.empty()) {
      out = std::move(unvisitedBlocks.back());
      unvisitedBlocks.pop_back();

      // In Basic mode, skip blocks that already have instructions
      // (they were processed in a previous iteration).
      if (getControlFlow() == ControlFlow::Basic && !out.block->empty() &&
          filter) {
        printvalue2("not empty ;D ");
        continue;
      }

      printvalue2("adding :" + std::to_string(out.block_address) +
                  out.block->getName());
      visitedAddresses.insert(out.block_address);
      blockInfo = out;
      return true;
    }
    return false;
  }

  void writeFunctionToFile(const std::string filename) {

    std::error_code EC_noopt;
    llvm::raw_fd_ostream OS_noopt(filename, EC_noopt);
    fnc->getParent()->print(OS_noopt, nullptr);
  }

  // ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions;
  // Memoization cache for computePossibleValues, cleared per solvePath call.
  llvm::DenseMap<llvm::Value*, std::set<llvm::APInt, APIntComparator>> pv_cache;
  llvm::DenseMap<uint64_t, ValueByteReference> buffer;
  using flagManager = std::array<LazyValue, FLAGS_END>;
  // llvm::DenseMap<Value*, flagManager> flagbuffer;

  flagManager FlagList;
  RegisterManagerConcolic<Register> Registers;

  llvm::DomConditionCache* DC = new llvm::DomConditionCache();

  unsigned int instct = 0;
  LiftStats liftStats;
  llvm::SimplifyQuery* cachedquery;

  llvm::BasicBlock* lastBB = nullptr;
  unsigned int BIlistsize = 0;

  std::map<uint64_t, uint64_t> pageMap;
  std::vector<llvm::BranchInst*> BIlist;

  // Set by branchHelper after resolving a conditional branch.
  // Test framework reads this to verify jcc taken/not-taken.
  bool hadConditionalBranch = false;
  bool lastConditionalBranchResolved = false;
  bool lastBranchTaken = false;
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

    GEPinfo(const GEPinfo& other)
        : addr(other.addr), type(other.type), TEB(other.TEB){};

    GEPinfo(GEPinfo& other)
        : addr(other.addr), type(other.type), TEB(other.TEB){};

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
        return GEPinfo(nullptr, static_cast<uint8_t>(-1), true);
      }
    };
  };
  llvm::DenseMap<GEPinfo, Value*, typename GEPinfo::GEPinfoKeyInfo> GEPcache;
  std::vector<llvm::Instruction*> memInfos;

  // todo : std::set
  std::vector<BBInfo> unvisitedBlocks;
  std::set<uint64_t> visitedAddresses;
  llvm::DenseMap<uint64_t, llvm::BasicBlock*> addrToBB;

  // creates an edge to created bb
  // TODO: wrapper for createbr, condbr, switch and update it there.
  BasicBlock* getOrCreateBB(uint64_t addr, std::string name) {
    if (getControlFlow() == ControlFlow::Basic) {
      auto it = addrToBB.find(addr);
      if (it != addrToBB.end()) {
        // also might have to update here,
        return it->second;
      }
    }
    auto bb = BasicBlock::Create(context, name, fnc);
    addrToBB[addr] = bb;
    DTU->applyUpdates({{DominatorTree::Insert, this->blockInfo.block, bb}});

    return bb;
  }

  // global
  llvm::LLVMContext context;
  llvm::Value* memoryAlloc;
  llvm::Function* fnc;
  llvm::Module* M;
  llvm::BasicBlock* bb;

protected:
  void createFunction() {
    return static_cast<Derived*>(this)->createFunction_impl();
  }

  void InitRegisters() {

    return static_cast<Derived*>(this)->InitRegisters_impl();
  }

  llvm::Value* getFlagValue(Flag f) {
    return static_cast<Derived*>(this)->GetFlagValue_impl(f);
  }
  void setFlagValue(Flag f, Value* v) {
    return static_cast<Derived*>(this)->SetFlagValue_impl(f, v);
  }

  constexpr ControlFlow getControlFlow() {
    return static_cast<Derived*>(this)->getControlFlow_impl();
  }

public:
  AliasAnalysis* AA;
  DominatorTree* DT;
  PostDominatorTree* PDT;
  DomTreeUpdater* DTU;
  MemorySSA* MSSA;
  MemorySSAUpdater* MSSAU;
  TargetLibraryInfo* TLI;
  AssumptionCache* AC;
  TargetTransformInfo* TTI;
  lifterClassBase() {
    static_assert(lifterConcept<Derived, Register>,
                  "Derived should satisfy lifterConcept");
    M = new llvm::Module("lifter_module", context);

    createFunction();
    this->bb = llvm::BasicBlock::Create(this->context, "entry", this->fnc);

    llvm::InstSimplifyFolder Folder(this->M->getDataLayout());

    this->builder = std::make_unique<llvm::IRBuilder<llvm::InstSimplifyFolder>>(
        this->bb, Folder);
    InitRegisters();
    TargetLibraryInfoImpl TLIImpl(Triple(fnc->getParent()->getTargetTriple()));
    TLI = new TargetLibraryInfo(TLIImpl);

    AA = new AliasAnalysis(*TLI);
    DT = new DominatorTree(*fnc);
    PDT = new PostDominatorTree(*fnc);
    DTU = new DomTreeUpdater(DT, PDT, DomTreeUpdater::UpdateStrategy::Lazy);
    MSSA = new MemorySSA(*fnc, AA, DT);
    MSSAU = new MemorySSAUpdater(MSSA);

    TTI = new TargetTransformInfo(fnc->getParent()->getDataLayout());
    AC = new AssumptionCache(*fnc, TTI);
  };

  ~lifterClassBase() {
    // LLVM analysis objects have interdependent destructors (MemorySSA
    // references DT and AA, MSSAU references MSSA, etc.). Deleting in any
    // order risks use-after-free inside LLVM's own teardown. Since this is
    // a CLI process that exits after the pipeline, we intentionally leak
    // these allocations. The OS reclaims everything on process exit.
    //
    // TODO: Migrate to unique_ptr with a custom deleter that tears down in
    // dependency order, or use LLVM's AnalysisManager which handles this.
  }

  lifterClassBase(const lifterClassBase& other) = delete;

  void liftInstruction();
  void liftInstructionSemantics();
  void branchHelper(llvm::Value* condition, const std::string& instname,
                    const int numbered, const bool reverse = false);

  std::optional<llvm::Value*> evaluateLLVMExpression(llvm::Value* value);

  // getters-setters
  void setFlag(const Flag flag, llvm::Value* newValue);
  void setFlagUndef(const Flag flag) {
    auto undef = UndefValue::get(builder->getInt1Ty());
    FlagList[flag].set(undef); // Set the new value directly
  }

  void setFlag(const Flag flag, std::function<llvm::Value*()> calculation);
  LazyValue getLazyFlag(const Flag flag);
  llvm::Value* getFlag(const Flag flag);
  llvm::Value* GetValueFromHighByteRegister(Register reg);
  llvm::Value* GetRegisterValue(const Register key);

protected:
  llvm::Value* GetRegisterValue_internal(const Register key) {
    return static_cast<Derived*>(this)->GetRegisterValue_impl(key);
  }
  void SetRegisterValue_internal(const Register key, llvm::Value* val) {
    return static_cast<Derived*>(this)->SetRegisterValue_impl(key, val);
  }

public:
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

  template <uint8_t count, bool little_endian = true>
  Value* LoadValueFromMemByBytes(llvm::Value* address) {
    llvm::Value* returnv = builder->getIntN(count * 8, 0);
    for (int i = 0; i < count; i++) {

      auto offset =
          builder->getIntN(address->getType()->getIntegerBitWidth(), i);

      auto pointer = getPointer(createAddFolder(address, offset));

      loadMemoryOp(pointer);
      printvalue(pointer);
      LazyValue retval([this, pointer]() {
        auto ret = builder->CreateLoad(builder->getIntNTy(8),
                                       pointer /*, "Loadxd-" + address + "-"*/);
        return ret;
      });

      if (Value* solvedLoad = solveLoad(retval, pointer, 8)) {
        printvalue(solvedLoad);
        if constexpr (little_endian) {
          // shl by i,
          solvedLoad = createShlFolder(
              createZExtFolder(solvedLoad, builder->getIntNTy(count * 8)),
              i * 8);

        } else {
          // shl by count-i-1*8
          solvedLoad = createShlFolder(
              createZExtFolder(solvedLoad, builder->getIntNTy(count * 8)),
              (count - 1 - i) * 8);
        }
        printvalue(returnv);
        printvalue(solvedLoad);
        Value* lhsPrev;
        ConstantInt* ci = builder->getIntN(count * 8, 0);
        if (llvm::PatternMatch::match(
                returnv, llvm::PatternMatch::m_ZExt(llvm::PatternMatch::m_Trunc(
                             llvm::PatternMatch::m_Value(lhsPrev)))) &&
            llvm::PatternMatch::match(solvedLoad,
                                      llvm::PatternMatch::m_ConstantInt(ci))) {
          printvalue2("0, postreturn");
          returnv = createTruncFolder(lhsPrev, builder->getIntNTy(count * 8));
        } else {
          printvalue2("1, postreturn");

          returnv = createOrFolder(returnv, solvedLoad);
        }
      } else {
        returnv = createOrFolder(returnv, retval.get());
      }
    }
    return returnv;
  }

  template <int count, bool little_endian = true>
  void StoreValueToMemByBytes(llvm::Value* address, llvm::Value* value) {
    printvalue(value);
    for (int i = 0; i < count; i++) {
      llvm::Value* storeval = nullptr;
      auto offset =
          builder->getIntN(address->getType()->getIntegerBitWidth(), i);
      auto pointer = getPointer(createAddFolder(address, offset));
      if constexpr (little_endian) {

        storeval = createTruncFolder(createLShrFolder(value, (i) * 8),
                                     builder->getIntNTy(8));
      } else {
        storeval =
            createTruncFolder(createLShrFolder(value, (count - 1 - i) * 8),
                              builder->getIntNTy(8));
      }
      printvalue(storeval);
      auto store = builder->CreateStore(storeval, pointer);
      insertMemoryOp(cast<StoreInst>(store));
    }
  }

  void SetMemoryValue(llvm::Value* address, llvm::Value* value);
  void SetRFLAGSValue(llvm::Value* value);
  PATH_info solvePath(llvm::Function* function, uint64_t& dest,
                      llvm::Value* simplifyValue);
  llvm::Value* popStack(int size);
  void pushFlags(const std::vector<llvm::Value*>& value,
                 const std::string& address);
  std::vector<llvm::Value*> GetRFLAGS();


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

  llvm::Value* createLoad(llvm::Value* ptr) {
    //
    return nullptr;
  }
  void createStore(llvm::Value* ptr, llvm::Value* val) {
    //
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

  // Apply post-call ABI effects: write return value, clobber volatile regs.
  void applyPostCallEffects(llvm::Value* callResult,
                            const CallEffects<Register>& fx);

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

  void markMemPaged(uint64_t start, uint64_t end) {
    pageMap[start] = end;
  }

  bool isMemPaged(uint64_t address) {
    auto it = pageMap.upper_bound(address);
    if (it == pageMap.begin())
      return false;

    --it;
    return address >= it->first && address < it->second;
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

  void run_opts();
  // end folders

#define OPCODE(fncname, ...) DEFINE_FUNCTION(fncname);
#include "x86_64_opcodes.x"
#undef OPCODE

  // end semantics definition
};

#undef DEFINE_FUNCTION
#endif // LIFTERCLASS_H