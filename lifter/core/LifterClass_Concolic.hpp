#ifndef LIFTERCLASS_CONCRETE_H
#define LIFTERCLASS_CONCRETE_H
#include "CommonDisassembler.hpp"
#include "RegisterManager.hpp"
#include "IcedDisassembler.hpp"
#include "IcedDisassemblerMnemonics.h"
#include "IcedDisassemblerRegisters.h"
#include "LifterClass.hpp"
#include <magic_enum/magic_enum.hpp>

template <
#ifdef ICED_FOUND
    Registers Register = Mergen::IcedRegister,
    Mnemonics Mnemonic = Mergen::IcedMnemonics,
    template <typename, typename> class DisassemblerBase =
        Mergen::icedDisassembler
#else

    Registers Register = Mergen::ZydisRegister,
    Mnemonics Mnemonic = Mergen::ZydisMnemonic,
    template <typename, typename> class DisassemblerBase =
        Mergen::ZydisDisassembler
#endif
    >

  requires Disassembler<DisassemblerBase<Mnemonic, Register>, Mnemonic,
                        Register>

class lifterConcolic : public lifterClassBase<
                           lifterConcolic<Register, Mnemonic, DisassemblerBase>,
                           Mnemonic, Register, DisassemblerBase> {
public:
  // lifterConcolic constructor will be executed after lifterClassBase
  // https://godbolt.org/z/f986zK5j1

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
    XMM0_ = 18,
    XMM1_ = 19,
    XMM2_ = 20,
    XMM3_ = 21,
    XMM4_ = 22,
    XMM5_ = 23,
    XMM6_ = 24,
    XMM7_ = 25,
    XMM8_ = 26,
    XMM9_ = 27,
    XMM10_ = 28,
    XMM11_ = 29,
    XMM12_ = 30,
    XMM13_ = 31,
    XMM14_ = 32,
    XMM15_ = 33,
    REGISTER_COUNT // Total number of registers
  };
  std::array<llvm::Value*, REGISTER_COUNT> vec;
  std::array<llvm::Value*, FLAGS_END> vecflag;

  int getRegisterIndex(Register key) const {

    switch (key) {
    case Register::EIP:
    case Register::RIP: {
      return RIP_;
    }
    case Register::EFLAGS:
    case Register::RFLAGS: {
      return RFLAGS_;
    }
    default: {
      if (key >= Register::RAX && key <= Register::R15) {
        return (static_cast<int>(key) - static_cast<int>(Register::RAX));
      }

      if (key >= Register::XMM0 && key <= Register::XMM15) {
        return XMM0_ + (static_cast<int>(key) - static_cast<int>(Register::XMM0));
      }

      UNREACHABLE("unsupported register index in concolic register manager");
      return RAX_;
    }
    }
  }

  llvm::Value* get_impl(Register key) {
    int index = getRegisterIndex(key);

    return vec[index];
  }

  void set_impl(Register key, llvm::Value* val) {
    // printvalue2(int(key));
    // printvalue2(magic_enum::enum_name(key))
    int keyindex = getRegisterIndex(key);
    // printvalue2(keyindex);
    // printvalue(val);
    vec[keyindex] = val;
  }

  void init_impl(
      std::array<std::pair<Register, llvm::Value*>, REGISTER_COUNT> values) {
    for (auto& [reg, val] : values) {
      int index = getRegisterIndex(reg);
      vec[index] = val;
    }
  }
  llvm::Value* get_flag_impl(Flag key) {
    auto val = vecflag[static_cast<uint8_t>(key)];
    if (val)
      return val;
    return ConstantInt::getSigned(Type::getInt1Ty(this->context), 0);
  }
  void set_flag_impl(Flag key, llvm::Value* val) {
    if (val->getType()->getIntegerBitWidth() > 1)
      val = this->builder->CreateTrunc(val, this->builder->getIntNTy(1));
    vecflag[static_cast<uint8_t>(key)] = val;
  }
  void
  init_flag_impl(std::array<std::pair<Flag, llvm::Value*>, FLAGS_END> values) {
    for (auto& [reg, val] : values) {
      vec[static_cast<uint8_t>(reg)] = val;
    }
  }

  llvm::Value* GetRegisterValue_impl(Register key) { return get_impl(key); }
  void SetRegisterValue_impl(Register key, llvm::Value* val) {

    set_impl(key, val);
  }

  llvm::Value* GetFlagValue_impl(Flag key) { return get_flag_impl(key); }

  void SetFlagValue_impl(Flag key, llvm::Value* v) { set_flag_impl(key, v); }

  llvm::BasicBlock* activeGeneralizedLoopEntrySourceBlock = nullptr;

  constexpr ControlFlow getControlFlow_impl() { return ControlFlow::Unflatten; }

  struct backup_point {
    std::array<llvm::Value*, REGISTER_COUNT> vec;
    std::array<llvm::Value*, FLAGS_END> vecflag;
    llvm::DenseMap<uint64_t, ValueByteReference> buffer;
    InstructionCache cache;
    llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions;
    uint64_t ct;
    llvm::BasicBlock* sourceBlock;

    bool operator==(const backup_point& other) const {
      if (buffer != other.buffer)
        return false;
      return vec == other.vec && vecflag == other.vecflag &&
             sourceBlock == other.sourceBlock;
    }

    backup_point(backup_point& other)
        : vec(other.vec), vecflag(other.vecflag), buffer(other.buffer),
          cache(other.cache), assumptions(other.assumptions), ct(other.ct),
          sourceBlock(other.sourceBlock){};

    backup_point(backup_point&& other) noexcept
        : vec(std::move(other.vec)), vecflag(std::move(other.vecflag)),
          buffer(std::move(other.buffer)), cache(std::move(other.cache)),
          assumptions(other.assumptions), ct(other.ct),
          sourceBlock(other.sourceBlock) {}

    backup_point(std::array<llvm::Value*, REGISTER_COUNT> vec,
                 std::array<llvm::Value*, FLAGS_END> vecflag,
                 llvm::DenseMap<uint64_t, ValueByteReference> buffer,
                 InstructionCache cc,
                 llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions,
                 uint64_t ct, llvm::BasicBlock* sourceBlock)
        : vec(vec), vecflag(vecflag), buffer(buffer), cache(cc),
          assumptions(assumptions), ct(ct), sourceBlock(sourceBlock){};
    backup_point() = default;
    backup_point(const backup_point&) = default;
    backup_point& operator=(const backup_point&) = default;
    backup_point& operator=(backup_point&&) noexcept = default;
  };

  llvm::DenseMap<BasicBlock*, backup_point> BBbackup;
  // Backedge-side state is a variable-width vector keyed by header. A loop
  // header may be reached from multiple backedges - each distinct backedge
  // sourceBlock contributes its own backup_point. Size 1 is the common
  // 2-way loop case (canonical + single backedge). Size >=2 is a multi-way
  // loop (e.g. a VM dispatcher whose body has several handler tails that
  // all jump back to the same header).
  llvm::DenseMap<BasicBlock*, llvm::SmallVector<backup_point, 2>> generalizedLoopBackedgeBackup;

  llvm::DenseMap<BasicBlock*, std::array<llvm::PHINode*, REGISTER_COUNT>>
      generalizedLoopRegisterPhis;
  llvm::DenseMap<BasicBlock*, std::array<llvm::PHINode*, FLAGS_END>>
      generalizedLoopFlagPhis;
  llvm::DenseMap<uint64_t, ValueByteReference> activeGeneralizedLoopLocalBuffer;
  // A non-primary loop-carried memory qword: tracked across the loop boundary
  // with per-backedge values, but not the primary dispatcher control cursor.
  // Used by the generalized retrieve helpers to build phis for all varying
  // memory slots, not just the first two (control + target).
  struct LoopCarriedSlot {
    uint64_t address = 0;
    uint64_t canonicalValue = 0;
    llvm::SmallVector<uint64_t, 2> backedgeValues;
  };

  struct GeneralizedLoopControlFieldState {
    bool valid = false;
    llvm::BasicBlock* headerBlock = nullptr;
    llvm::BasicBlock* canonicalSource = nullptr;
    // Backedge side is variable-width; see generalizedLoopBackedgeBackup.
    llvm::SmallVector<llvm::BasicBlock*, 2> backedgeSources;
    uint64_t canonicalControl = 0;
    llvm::SmallVector<uint64_t, 2> backedgeControls;
    llvm::DenseMap<uint64_t, ValueByteReference> canonicalBuffer;
    llvm::SmallVector<llvm::DenseMap<uint64_t, ValueByteReference>, 2> backedgeBuffers;
    // Per-loop-discovered memory slots (Phase A: seeded to the Themida defaults
    // by the populator; Phase B will replace the seed with active discovery).
    // controlSlot is the qword whose value advances across loop iterations and
    // drives the dispatcher cursor; targetSlot is the loop-carried output slot
    // consumed by retrieve_generalized_loop_target_slot_value_impl.
    uint64_t controlSlot = 0;
    uint64_t targetSlot = 0;
    // Additional loop-carried memory slots beyond controlSlot/targetSlot.
    // Each varying qword discovered during slot discovery gets an entry here
    // so retrieve helpers can build phis for ALL loop-carried state, not just
    // the primary two. This fixes the TEA-round class of bugs where a third+
    // varying slot was silently dropped.
    llvm::SmallVector<LoopCarriedSlot, 4> carriedSlots;
  } activeGeneralizedLoopControlFieldState;
  llvm::DenseMap<llvm::BasicBlock*, GeneralizedLoopControlFieldState>
      generalizedLoopControlFieldStates;
  static constexpr uint64_t kThemidaControlCursorSlot = 0x14004DD19ULL;
  static constexpr uint64_t kThemidaLoopCarriedSlot = 0x14004DC67ULL;
  static constexpr std::array<uint64_t, 3> kSupportedGeneralizedControlFieldOffsets = {
      0x6ULL, 0xAULL, 0xCULL};
  bool readConstantTrackedQword(
      const llvm::DenseMap<uint64_t, ValueByteReference>& src, uint64_t qwordStart,
      uint64_t& out) {
    llvm::APInt combined(64, 0);
    for (uint8_t i = 0; i < 8; ++i) {
      auto it = src.find(qwordStart + i);
      if (it == src.end() || !it->second.value) {
        return false;
      }
      auto* ci = llvm::dyn_cast<llvm::ConstantInt>(it->second.value);
      if (!ci) {
        return false;
      }
      auto byteValue = ci->getValue().lshr(it->second.byteOffset * 8).trunc(8);
      combined |= byteValue.zext(64).shl(i * 8);
    }
    out = combined.getZExtValue();
    return true;
  }
  llvm::Value* retrieveContiguousBufferedValue(
      const llvm::DenseMap<uint64_t, ValueByteReference>& sourceBuffer,
      uint64_t startAddress, uint8_t byteCount) {
    auto firstIt = sourceBuffer.find(startAddress);
    if (firstIt == sourceBuffer.end() || !firstIt->second.value) {
      return nullptr;
    }
    auto* sharedValue = firstIt->second.value;
    uint8_t firstByteOffset = firstIt->second.byteOffset;
    for (uint8_t i = 0; i < byteCount; ++i) {
      auto it = sourceBuffer.find(startAddress + i);
      if (it == sourceBuffer.end() || !it->second.value ||
          it->second.value != sharedValue ||
          it->second.byteOffset != firstByteOffset + i) {
        return nullptr;
      }
    }
    return this->extractBytes(sharedValue, firstByteOffset,
                              firstByteOffset + byteCount);
  }
  llvm::Value* retrieveValueFromBufferSlice(
      const llvm::DenseMap<uint64_t, ValueByteReference>& sourceBuffer,
      uint64_t startAddress, uint8_t byteCount) {
    auto firstIt = sourceBuffer.find(startAddress);
    if (firstIt == sourceBuffer.end() || !firstIt->second.value) {
      return nullptr;
    }

    bool contiguousSingleValue = true;
    auto* sharedValue = firstIt->second.value;
    uint8_t firstByteOffset = firstIt->second.byteOffset;
    for (uint8_t i = 0; i < byteCount; ++i) {
      auto it = sourceBuffer.find(startAddress + i);
      if (it == sourceBuffer.end() || !it->second.value) {
        return nullptr;
      }
      if (it->second.value != sharedValue ||
          it->second.byteOffset != firstByteOffset + i) {
        contiguousSingleValue = false;
      }
    }
    if (contiguousSingleValue) {
      return this->extractBytes(sharedValue, firstByteOffset,
                                firstByteOffset + byteCount);
    }

    llvm::Value* result = llvm::ConstantInt::get(
        llvm::Type::getIntNTy(this->context, byteCount * 8), 0);
    for (uint8_t i = 0; i < byteCount; ++i) {
      auto it = sourceBuffer.find(startAddress + i);
      auto* byteValue = this->extractBytes(it->second.value, it->second.byteOffset,
                                           it->second.byteOffset + 1);
      if (!byteValue) {
        return nullptr;
      }
      auto* shiftedByteValue = this->createShlFolder(
          this->createZExtOrTruncFolder(
              byteValue, llvm::Type::getIntNTy(this->context, byteCount * 8)),
          llvm::APInt(byteCount * 8, i * 8));
      result = this->createOrFolder(result, shiftedByteValue,
                                    "generalized-local-byte");
    }
    return result;
  }
  llvm::Value* retrieveBufferedOrConcreteValue(
      const llvm::DenseMap<uint64_t, ValueByteReference>& sourceBuffer,
      uint64_t startAddress, uint8_t byteCount) {
    if (auto* buffered =
            retrieveValueFromBufferSlice(sourceBuffer, startAddress, byteCount)) {
      return buffered;
    }
    uint64_t normalizedAddress = this->normalizeRuntimeTargetAddress(startAddress);
    if (normalizedAddress != startAddress) {
      if (auto* normalizedBuffered =
              retrieveValueFromBufferSlice(sourceBuffer, normalizedAddress, byteCount)) {
        return normalizedBuffered;
      }
    }
    uint64_t concreteValue = 0;
    if (!this->file.readMemory(startAddress, byteCount, concreteValue)) {
      if (normalizedAddress == startAddress ||
          !this->file.readMemory(normalizedAddress, byteCount, concreteValue)) {
        return nullptr;
      }
    }
    return this->builder->getIntN(byteCount * 8, concreteValue);
  }
  void clearGeneralizedLoopControlFieldState() {
    activeGeneralizedLoopEntrySourceBlock = nullptr;
    activeGeneralizedLoopControlFieldState.valid = false;
    activeGeneralizedLoopControlFieldState.headerBlock = nullptr;
    activeGeneralizedLoopControlFieldState.canonicalSource = nullptr;
    activeGeneralizedLoopControlFieldState.backedgeSources.clear();
    activeGeneralizedLoopControlFieldState.canonicalControl = 0;
    activeGeneralizedLoopControlFieldState.backedgeControls.clear();
    activeGeneralizedLoopControlFieldState.controlSlot = 0;
    activeGeneralizedLoopControlFieldState.targetSlot = 0;
    activeGeneralizedLoopControlFieldState.canonicalBuffer.clear();
    activeGeneralizedLoopControlFieldState.backedgeBuffers.clear();
    activeGeneralizedLoopControlFieldState.carriedSlots.clear();
  }
  bool evaluateConcreteGeneralizedLoopInt(llvm::Value* candidate,
                                          llvm::BasicBlock* incomingBlock,
                                          llvm::APInt& out) {
    if (!candidate || !incomingBlock) {
      return false;
    }
    if (auto* constantInt = llvm::dyn_cast<llvm::ConstantInt>(candidate)) {
      out = constantInt->getValue();
      return true;
    }
    if (auto* phi = llvm::dyn_cast<llvm::PHINode>(candidate)) {
      int incomingIndex = phi->getBasicBlockIndex(incomingBlock);
      if (incomingIndex < 0) {
        return false;
      }
      return evaluateConcreteGeneralizedLoopInt(phi->getIncomingValue(incomingIndex),
                                                incomingBlock, out);
    }
    if (auto* castInst = llvm::dyn_cast<llvm::CastInst>(candidate)) {
      llvm::APInt operandValue(1, 0);
      if (!evaluateConcreteGeneralizedLoopInt(castInst->getOperand(0), incomingBlock,
                                              operandValue)) {
        return false;
      }
      const unsigned width = castInst->getType()->getIntegerBitWidth();
      switch (castInst->getOpcode()) {
      case llvm::Instruction::Trunc:
        out = operandValue.trunc(width);
        return true;
      case llvm::Instruction::ZExt:
        out = operandValue.zext(width);
        return true;
      case llvm::Instruction::SExt:
        out = operandValue.sext(width);
        return true;
      default:
        return false;
      }
    }
    if (auto* binOp = llvm::dyn_cast<llvm::BinaryOperator>(candidate)) {
      llvm::APInt lhsValue(1, 0);
      llvm::APInt rhsValue(1, 0);
      if (!evaluateConcreteGeneralizedLoopInt(binOp->getOperand(0), incomingBlock,
                                              lhsValue) ||
          !evaluateConcreteGeneralizedLoopInt(binOp->getOperand(1), incomingBlock,
                                              rhsValue)) {
        return false;
      }
      const unsigned width = binOp->getType()->getIntegerBitWidth();
      auto lhs = lhsValue.zextOrTrunc(width);
      auto rhs = rhsValue.zextOrTrunc(width);
      switch (binOp->getOpcode()) {
      case llvm::Instruction::Add:
        out = lhs + rhs;
        return true;
      case llvm::Instruction::Sub:
        out = lhs - rhs;
        return true;
      case llvm::Instruction::And:
        out = lhs & rhs;
        return true;
      case llvm::Instruction::Or:
        out = lhs | rhs;
        return true;
      case llvm::Instruction::Xor:
        out = lhs ^ rhs;
        return true;
      case llvm::Instruction::Shl:
        out = lhs.shl(rhs.getLimitedValue(width));
        return true;
      case llvm::Instruction::LShr:
        out = lhs.lshr(rhs.getLimitedValue(width));
        return true;
      default:
        return false;
      }
    }
    return false;
  }
  bool evaluateConcreteGeneralizedLoopInt(llvm::Value* candidate,
                                          llvm::BasicBlock* incomingBlock,
                                          uint64_t& out) {
    llvm::APInt value(1, 0);
    if (!evaluateConcreteGeneralizedLoopInt(candidate, incomingBlock, value)) {
      return false;
    }
    out = value.zextOrTrunc(64).getZExtValue();
    return true;
  }
  llvm::Value* stripIntegerCastsForGeneralizedLoad(llvm::Value* candidate) {
    while (auto* castInst = llvm::dyn_cast<llvm::CastInst>(candidate)) {
      auto* srcTy = castInst->getOperand(0)->getType();
      auto* dstTy = castInst->getType();
      if (!srcTy->isIntegerTy() || !dstTy->isIntegerTy()) {
        break;
      }
      candidate = castInst->getOperand(0);
    }
    return candidate;
  }
  bool matchGeneralizedLoopControlFieldAddress(llvm::Value* loadOffset,
                                               uint64_t& fieldOffsetOut) {
    llvm::Value* baseCandidate = nullptr;
    uint64_t constantOffset = 0;
    auto collectTerms = [&](auto&& self, llvm::Value* candidate) -> bool {
      candidate = stripIntegerCastsForGeneralizedLoad(candidate);
      if (auto* addInst = llvm::dyn_cast<llvm::BinaryOperator>(candidate);
          addInst && addInst->getOpcode() == llvm::Instruction::Add) {
        return self(self, addInst->getOperand(0)) &&
               self(self, addInst->getOperand(1));
      }
      if (auto* constantInt = llvm::dyn_cast<llvm::ConstantInt>(candidate)) {
        constantOffset += constantInt->getZExtValue();
        return true;
      }
      if (baseCandidate) {
        return false;
      }
      baseCandidate = candidate;
      return true;
    };
    if (!collectTerms(collectTerms, loadOffset) || !baseCandidate) {
      return false;
    }
    const bool supportedOffset = llvm::is_contained(
        kSupportedGeneralizedControlFieldOffsets, constantOffset);
    if (!supportedOffset) {
      return false;
    }
    auto* loadInst = llvm::dyn_cast<llvm::LoadInst>(baseCandidate);
    if (!loadInst || !loadInst->getType()->isIntegerTy(64)) {
      return false;
    }
    auto* gep =
        llvm::dyn_cast<llvm::GetElementPtrInst>(loadInst->getPointerOperand());
    if (!gep || gep->getPointerOperand() != this->memoryAlloc) {
      return false;
    }
    auto* offsetCI = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1));
    if (!offsetCI ||
        offsetCI->getZExtValue() !=
            activeGeneralizedLoopControlFieldState.controlSlot) {
      return false;
    }
    fieldOffsetOut = constantOffset;
    return true;
  }


  llvm::DenseMap<uint64_t, ValueByteReference> extractLocalStackBuffer(
      const llvm::DenseMap<uint64_t, ValueByteReference>& sourceBuffer) {
    llvm::DenseMap<uint64_t, ValueByteReference> localBuffer;
    for (const auto& entry : sourceBuffer) {
      if (this->isTrackedLocalStackAddress(entry.first)) {
        localBuffer[entry.first] = entry.second;
      }
    }
    return localBuffer;
  }


  // Data-driven register preservation: a register is preserved (not widened
  // to undef on the first backedge) when its value differs between canonical
  // and any effective backedge — meaning the loop body carries state through
  // that register. RSP is always preserved regardless.
  //
  // For dispatcher-shaped loops (IndirectJump context), the Themida-tuned
  // hardcoded set {1,4,7,9,10,12,14} is used instead. Preserving ALL
  // differing registers in dispatchers prevents LLVM from optimizing away
  // scratch computations, which blocks import resolution.
  bool shouldPreserveGeneralizedBackedgeRegister(
      size_t index, const backup_point& canonical,
      llvm::ArrayRef<const backup_point*> effectiveSources,
      bool dispatcherShaped) const {
    // RSP is unconditionally preserved so the stack pointer is never
    // treated as "could be anything" inside the loop body.
    if (index == RSP_) return true;
    if (dispatcherShaped) {
      // Legacy Themida-tuned set: only these registers carry dispatcher
      // state that must survive widening. All others widen to undef so
      // LLVM can fold away scratch noise and resolve import targets.
      switch (index) {
      case 1:  // RCX
      case 7:  // RDI
      case 9:  // R9
      case 10: // R10
      case 12: // R12
      case 14: // R14
        return true;
      default:
        return false;
      }
    }
    // Data-driven: preserve when any backedge has a different SSA value
    // from canonical. ConstantInts with the same numeric value share a
    // pointer in LLVM, so pointer equality is a sound test for constants.
    for (const auto* src : effectiveSources) {
      if (src->vec[index] != canonical.vec[index]) {
        return true;
      }
    }
    return false;
  }

  backup_point make_generalized_loop_backup(BasicBlock* bb,
                                            const backup_point& canonical,
                                            llvm::ArrayRef<backup_point> sources,
                                            bool dispatcherShaped = false) {
    // Use the first source as the base for the generalized snapshot shape
    // (buffer, counter, etc.). For 2-way loops this matches the original
    // single-source behavior exactly; for N-way we pick sources[0] as the
    // representative snapshot since the caller must restore a coherent view.
    // No backedges: canonical-only path. Return canonical with local-stack
    // addresses filtered, matching the pre-N-way fallback where
    // make_generalized_loop_backup was called with canonical as both args.
    if (sources.empty()) {
      backup_point generalized = canonical;
      llvm::DenseMap<uint64_t, ValueByteReference> filteredBuffer;
      for (const auto& entry : canonical.buffer) {
        if (!this->isTrackedLocalStackAddress(entry.first)) {
          filteredBuffer[entry.first] = entry.second;
        }
      }
      generalized.buffer = std::move(filteredBuffer);
      generalized.cache = InstructionCache();
      generalized.assumptions.clear();
      return generalized;
    }
    backup_point generalized = sources.front();
    llvm::DenseMap<uint64_t, ValueByteReference> filteredBuffer;
    filteredBuffer.reserve(sources.front().buffer.size());
    for (const auto& entry : sources.front().buffer) {
      if (!this->isTrackedLocalStackAddress(entry.first)) {
        filteredBuffer[entry.first] = entry.second;
      }
    }
    generalized.buffer = std::move(filteredBuffer);
    generalized.cache = InstructionCache();
    generalized.assumptions.clear();

    auto* canonicalSource = canonical.sourceBlock;
    if (!bb || !canonicalSource) {
      return generalized;
    }
    // Filter backedges: drop any that duplicate canonicalSource. This
    // preserves the existing 2-way "canonicalSource == backedgeSource"
    // bailout for the trivial degenerate case.
    llvm::SmallVector<const backup_point*, 2> effectiveSources;
    effectiveSources.reserve(sources.size());
    for (const auto& src : sources) {
      if (src.sourceBlock && src.sourceBlock != canonicalSource) {
        effectiveSources.push_back(&src);
      }
    }
    if (effectiveSources.empty()) {
      return generalized;
    }

    std::array<llvm::PHINode*, REGISTER_COUNT> registerPhis{};
    std::array<llvm::PHINode*, FLAGS_END> flagPhis{};
    llvm::IRBuilder<> phiBuilder(bb, bb->begin());
    auto mergeValue = [&](llvm::Value* canonicalValue,
                          llvm::ArrayRef<llvm::Value*> backedgeValues,
                          const char* name, llvm::PHINode*& phiOut,
                          bool widenFirstBackedge) -> llvm::Value* {
      // Require canonical + all backedges present and type-matched. Any
      // type mismatch or nullptr falls back to the first backedge value,
      // preserving the pre-N-way single-backedge semantics.
      if (!canonicalValue || backedgeValues.empty()) {
        return backedgeValues.empty() ? nullptr : backedgeValues.front();
      }
      for (auto* beValue : backedgeValues) {
        if (!beValue || beValue->getType() != canonicalValue->getType() ||
            beValue == canonicalValue) {
          return backedgeValues.front();
        }
      }
      auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                       1 + backedgeValues.size(), name);
      phi->addIncoming(canonicalValue, canonicalSource);
      for (size_t i = 0; i < backedgeValues.size(); ++i) {
        phi->addIncoming(widenFirstBackedge
                             ? llvm::UndefValue::get(backedgeValues[i]->getType())
                             : backedgeValues[i],
                         effectiveSources[i]->sourceBlock);
      }
      phiOut = phi;
      return phi;
    };
    constexpr std::array<Register, 16> gprOrder = {
        Register::RAX, Register::RCX, Register::RDX, Register::RBX,
        Register::RSP, Register::RBP, Register::RSI, Register::RDI,
        Register::R8,  Register::R9,  Register::R10, Register::R11,
        Register::R12, Register::R13, Register::R14, Register::R15,
    };

    llvm::SmallVector<llvm::Value*, 2> regValues;
    llvm::SmallVector<llvm::Value*, 2> flagValues;
    for (size_t i = 0; i < REGISTER_COUNT; ++i) {
      const bool widenFirstBackedge =
          !shouldPreserveGeneralizedBackedgeRegister(i, canonical,
                                                     effectiveSources,
                                                     dispatcherShaped);
      regValues.clear();
      for (auto* src : effectiveSources) {
        regValues.push_back(src->vec[i]);
      }
      generalized.vec[i] = mergeValue(canonical.vec[i], regValues,
                                      "loop_reg_phi", registerPhis[i],
                                      widenFirstBackedge);
    }
    for (size_t i = 0; i < FLAGS_END; ++i) {
      flagValues.clear();
      for (auto* src : effectiveSources) {
        flagValues.push_back(src->vecflag[i]);
      }
      generalized.vecflag[i] =
          mergeValue(canonical.vecflag[i], flagValues, "loop_flag_phi",
                     flagPhis[i], false);
    }
    generalizedLoopRegisterPhis[bb] = registerPhis;
    generalizedLoopFlagPhis[bb] = flagPhis;
    return generalized;
  }

  void restore_backup_point(const backup_point& snapshot) {
    vec = snapshot.vec;
    vecflag = snapshot.vecflag;
    this->buffer = snapshot.buffer;
    this->cache = snapshot.cache;
    this->assumptions = snapshot.assumptions;
    this->counter = snapshot.ct;
  }

  void branch_backup_impl(BasicBlock* bb, bool generalized) {
    printvalue2("backing up");
    printvalue2(this->counter);

    auto snapshot = backup_point(vec, vecflag, this->buffer, this->cache,
                                 this->assumptions, this->counter,
                                 this->builder->GetInsertBlock());
    if (generalized) {
      if (!BBbackup.contains(bb)) {
        BBbackup[bb] = snapshot;
      }
      // Append per-source; a repeat call from the same sourceBlock replaces
      // that block's entry in place, preserving uniqueness without growing
      // the vector unboundedly on iterative lift passes.
      auto& backedges = generalizedLoopBackedgeBackup[bb];
      for (auto& existing : backedges) {
        if (existing.sourceBlock == snapshot.sourceBlock) {
          existing = std::move(snapshot);
          return;
        }
      }
      backedges.push_back(std::move(snapshot));
      return;
    }

    BBbackup[bb] = std::move(snapshot);
  }

  void load_backup_impl(BasicBlock* bb) {
    activeGeneralizedLoopLocalBuffer.clear();
    if (BBbackup.contains(bb)) {
      printvalue2("loading backup");
      if (this->liftProgressDiagEnabled) {
        std::cout << "[diag] load_backup bb=" << bb->getName().str()
                  << " has14fca0=" << (BBbackup[bb].buffer.contains(1375392) ? 1 : 0)
                  << " has14fca8=" << (BBbackup[bb].buffer.contains(1375400) ? 1 : 0)
                  << " has14fcb0=" << (BBbackup[bb].buffer.contains(1375408) ? 1 : 0)
                  << "\n";
      }
      restore_backup_point(BBbackup[bb]);
      activeGeneralizedLoopEntrySourceBlock = BBbackup[bb].sourceBlock;
    }
  }

  // Result of generalized-loop slot discovery: control + target slot identity
  // and the canonical/backedge qword values + per-backedge buffers that
  // motivate the choice. backedgeSources/Controls/Buffers are filled with
  // exactly the backedges whose tracked qword at controlSlot differs from
  // canonical (the activation precondition for the loop-control helpers).
  struct DiscoveredGeneralizedLoopSlots {
    bool valid = false;
    uint64_t controlSlot = 0;
    uint64_t targetSlot = 0;
    uint64_t canonicalControl = 0;
    llvm::SmallVector<llvm::BasicBlock*, 2> backedgeSources;
    llvm::SmallVector<uint64_t, 2> backedgeControls;
    llvm::SmallVector<llvm::DenseMap<uint64_t, ValueByteReference>, 2> backedgeBuffers;
    // All non-primary varying qwords discovered during scan.
    llvm::SmallVector<LoopCarriedSlot, 4> carriedSlots;
  };

  // Try to populate `dst` from a specific candidate `slot`. Returns true iff
  // canonical has a tracked qword at slot AND at least one backedge has a
  // differing tracked qword at slot. Caller uses this both for the legacy
  // Themida-slot priority path and for the fallback scan.
  bool tryPopulateControlFromSlot(
      const backup_point& canonical,
      llvm::ArrayRef<backup_point> backedges, uint64_t slot,
      DiscoveredGeneralizedLoopSlots& dst) {
    uint64_t canonicalControl = 0;
    if (!readConstantTrackedQword(canonical.buffer, slot, canonicalControl)) {
      return false;
    }
    llvm::SmallVector<llvm::BasicBlock*, 2> sources;
    llvm::SmallVector<uint64_t, 2> controls;
    llvm::SmallVector<llvm::DenseMap<uint64_t, ValueByteReference>, 2> buffers;
    for (const auto& be : backedges) {
      if (!be.sourceBlock || be.sourceBlock == canonical.sourceBlock) {
        continue;
      }
      uint64_t beControl = 0;
      if (!readConstantTrackedQword(be.buffer, slot, beControl)) {
        continue;
      }
      if (beControl == canonicalControl) {
        continue;
      }
      sources.push_back(be.sourceBlock);
      controls.push_back(beControl);
      buffers.push_back(be.buffer);
    }
    if (sources.empty()) {
      return false;
    }
    dst.controlSlot = slot;
    dst.canonicalControl = canonicalControl;
    dst.backedgeSources = std::move(sources);
    dst.backedgeControls = std::move(controls);
    dst.backedgeBuffers = std::move(buffers);
    return true;
  }

  // Discover the loop's control + target memory slots from canonical and
  // backedge buffers. Order of preference for control slot:
  //   1. The legacy Themida cursor slot if it has a varying tracked qword
  //      (zero-regression guarantee on the reference Themida sample).
  //   2. Otherwise, the qword in the canonical buffer with the most-varying
  //      backedges. Tiebreak: lowest address.
  // Order of preference for target slot:
  //   1. The legacy Themida loop-carried slot if every selected backedge has
  //      a tracked qword there.
  //   2. Otherwise, the lowest-address candidate qword (excluding the chosen
  //      controlSlot) that is tracked across canonical and every selected
  //      backedge buffer. Values may match or differ; the target-slot helper
  //      handles both cases.
  // Returns a result with valid=false if no control slot can be identified.
  // Stack-local addresses are excluded from candidates; they are handled by
  // separate local-buffer machinery.
  DiscoveredGeneralizedLoopSlots discoverGeneralizedLoopSlots(
      const backup_point& canonical,
      llvm::ArrayRef<backup_point> backedges) {
    DiscoveredGeneralizedLoopSlots result;
    if (!canonical.sourceBlock || backedges.empty()) {
      return result;
    }

    // 1. Try the legacy Themida cursor slot first.
    if (!tryPopulateControlFromSlot(canonical, backedges,
                                    kThemidaControlCursorSlot, result)) {
      // 2. Fallback scan: enumerate qword-start addresses in canonical buffer
      //    and pick the most-varying. A "qword start" is an address A where
      //    canonical has 8 contiguous tracked bytes from A and has no key at
      //    A-1 (filters overlapping qwords from a single tracked region).
      llvm::SmallVector<uint64_t, 16> candidates;
      for (const auto& entry : canonical.buffer) {
        const uint64_t addr = entry.first;
        if (this->isTrackedStackAddress(addr)) continue;
        if (canonical.buffer.contains(addr - 1)) continue;
        uint64_t dummy = 0;
        if (!readConstantTrackedQword(canonical.buffer, addr, dummy)) continue;
        candidates.push_back(addr);
      }
      std::sort(candidates.begin(), candidates.end());
      size_t bestVarianceCount = 0;
      for (uint64_t addr : candidates) {
        DiscoveredGeneralizedLoopSlots probe;
        if (!tryPopulateControlFromSlot(canonical, backedges, addr, probe)) {
          continue;
        }
        if (probe.backedgeSources.size() > bestVarianceCount) {
          bestVarianceCount = probe.backedgeSources.size();
          result.controlSlot = probe.controlSlot;
          result.canonicalControl = probe.canonicalControl;
          result.backedgeSources = std::move(probe.backedgeSources);
          result.backedgeControls = std::move(probe.backedgeControls);
          result.backedgeBuffers = std::move(probe.backedgeBuffers);
        }
      }
      if (bestVarianceCount == 0) {
        return result;  // no varying qword anywhere -> no control slot
      }
    }
    result.valid = true;

    // Target slot: prefer legacy Themida carried slot if usable across all
    // selected backedges; otherwise scan for the lowest-addr alternative.
    auto targetUsableAt = [&](uint64_t slot) -> bool {
      if (slot == result.controlSlot) return false;
      uint64_t dummy = 0;
      if (!readConstantTrackedQword(canonical.buffer, slot, dummy)) return false;
      for (const auto& buf : result.backedgeBuffers) {
        if (!readConstantTrackedQword(buf, slot, dummy)) return false;
      }
      return true;
    };
    if (targetUsableAt(kThemidaLoopCarriedSlot)) {
      result.targetSlot = kThemidaLoopCarriedSlot;
    } else {
      llvm::SmallVector<uint64_t, 16> targetCandidates;
      for (const auto& entry : canonical.buffer) {
        const uint64_t addr = entry.first;
        if (this->isTrackedStackAddress(addr)) continue;
        if (canonical.buffer.contains(addr - 1)) continue;
        targetCandidates.push_back(addr);
      }
      std::sort(targetCandidates.begin(), targetCandidates.end());
      for (uint64_t addr : targetCandidates) {
        if (targetUsableAt(addr)) {
          result.targetSlot = addr;
          break;
        }
      }
    }

    // Collect ALL additional varying qwords beyond controlSlot/targetSlot.
    // Each gets a LoopCarriedSlot so retrieve helpers can build phis for
    // every loop-carried memory address, fixing the TEA-round class of bugs.
    {
      llvm::SmallVector<uint64_t, 16> allCandidates;
      for (const auto& entry : canonical.buffer) {
        const uint64_t addr = entry.first;
        if (this->isTrackedStackAddress(addr)) continue;
        if (canonical.buffer.contains(addr - 1)) continue;
        uint64_t dummy = 0;
        if (!readConstantTrackedQword(canonical.buffer, addr, dummy)) continue;
        allCandidates.push_back(addr);
      }
      std::sort(allCandidates.begin(), allCandidates.end());
      for (uint64_t addr : allCandidates) {
        if (addr == result.controlSlot || addr == result.targetSlot) continue;
        uint64_t canonVal = 0;
        if (!readConstantTrackedQword(canonical.buffer, addr, canonVal)) continue;
        // Collect per-backedge values at this address.
        // Unlike controlSlot, we include slots even when some backedges match
        // the canonical value — the helper will collapse to the shared value
        // when all match, and build a phi when any differ.
        bool anyBackedgeHasSlot = false;
        LoopCarriedSlot slot;
        slot.address = addr;
        slot.canonicalValue = canonVal;
        for (const auto& buf : result.backedgeBuffers) {
          uint64_t beVal = 0;
          if (readConstantTrackedQword(buf, addr, beVal)) {
            slot.backedgeValues.push_back(beVal);
            anyBackedgeHasSlot = true;
          } else {
            // Backedge buffer lacks this slot — skip entire slot to avoid
            // mismatched backedge vector sizes.
            anyBackedgeHasSlot = false;
            break;
          }
        }
        if (anyBackedgeHasSlot && !slot.backedgeValues.empty()) {
          result.carriedSlots.push_back(std::move(slot));
        }
      }
    }

    return result;
  }

  void load_generalized_backup_impl(BasicBlock* bb) {
    activeGeneralizedLoopLocalBuffer.clear();
    clearGeneralizedLoopControlFieldState();
    if (generalizedLoopBackedgeBackup.contains(bb) && BBbackup.contains(bb)) {
      printvalue2("loading generalized backup");
      auto& backedges = generalizedLoopBackedgeBackup[bb];
      // Discover the per-loop control + target slots from canonical and
      // backedge buffers. Falls back to the legacy Themida slots when they
      // qualify (zero behavior change on the reference Themida sample).
      auto discovery = discoverGeneralizedLoopSlots(BBbackup[bb], backedges);
      // Dispatcher-shaped loops (Themida-style) use the hardcoded register
      // preserve set; simple guest loops use data-driven preservation.
      // Dispatcher detection: check if this is a Themida-style dispatcher
      // where the hardcoded register preserve set should be used.
      // When discovery IS valid and the control slot is the Themida cursor,
      // it's definitely a dispatcher. When discovery is invalid (no varying
      // slots), check if the canonical buffer contains the cursor slot —
      // if so, it's likely a dispatcher that hasn't diverged yet.
      // Otherwise (no cursor slot in buffer at all), it's a guest loop.
      bool dispatcherShaped = false;
      if (discovery.valid) {
        dispatcherShaped = (discovery.controlSlot == kThemidaControlCursorSlot);
      } else {
        // No varying slots — check if the Themida cursor address is even
        // present in the canonical buffer (indicates a dispatcher that
        // hasn't fully diverged yet). Guest loops never write to the cursor.
        uint64_t cursorProbe = 0;
        dispatcherShaped = readConstantTrackedQword(
            BBbackup[bb].buffer, kThemidaControlCursorSlot, cursorProbe);
      }
      if (this->liftProgressDiagEnabled) {
        std::cout << "[diag] dispatcher_check valid=" << discovery.valid
                  << " controlSlot=0x" << std::hex << discovery.controlSlot
                  << " kThemida=0x" << kThemidaControlCursorSlot
                  << std::dec << " result=" << dispatcherShaped << "\n";
      }
      auto snapshot = make_generalized_loop_backup(bb, BBbackup[bb], backedges,
                                                   dispatcherShaped);
      if (this->liftProgressDiagEnabled) {
        auto formatHex = [](uint64_t value) {
          std::ostringstream os;
          os << "0x" << std::hex << std::uppercase << value;
          return os.str();
        };
        std::cout << "[diag] load_generalized_backup bb=" << bb->getName().str()
                  << " sourceCanonical="
                  << (BBbackup[bb].sourceBlock
                          ? BBbackup[bb].sourceBlock->getName().str()
                          : std::string("<null>"))
                  << " backedgeCount=" << backedges.size()
                  << " discovered="
                  << (discovery.valid ? "yes" : "no")
                  << " controlSlot="
                  << (discovery.valid ? formatHex(discovery.controlSlot)
                                      : std::string("na"))
                  << " targetSlot="
                  << (discovery.valid && discovery.targetSlot
                          ? formatHex(discovery.targetSlot)
                          : std::string("na"))
                  << " canonicalControl="
                  << (discovery.valid ? formatHex(discovery.canonicalControl)
                                      : std::string("na"));
        for (size_t i = 0; i < discovery.backedgeSources.size(); ++i) {
          std::cout << " backedge[" << i << "]source="
                    << (discovery.backedgeSources[i]
                            ? discovery.backedgeSources[i]->getName().str()
                            : std::string("<null>"))
                    << " backedge[" << i << "]control="
                    << formatHex(discovery.backedgeControls[i]);
        }
        std::cout << "\n";
      }
      restore_backup_point(snapshot);
      auto storedStateIt = generalizedLoopControlFieldStates.find(bb);
      if (storedStateIt != generalizedLoopControlFieldStates.end() &&
          storedStateIt->second.valid) {
        activeGeneralizedLoopControlFieldState = storedStateIt->second;
        activeGeneralizedLoopEntrySourceBlock =
            activeGeneralizedLoopControlFieldState.backedgeSources.empty()
                ? nullptr
                : activeGeneralizedLoopControlFieldState.backedgeSources.front();
        if (!activeGeneralizedLoopControlFieldState.backedgeBuffers.empty()) {
          activeGeneralizedLoopLocalBuffer = extractLocalStackBuffer(
              activeGeneralizedLoopControlFieldState.backedgeBuffers.front());
        } else {
          activeGeneralizedLoopLocalBuffer.clear();
        }
      } else {
        activeGeneralizedLoopEntrySourceBlock =
            backedges.empty() ? nullptr : backedges.front().sourceBlock;
        activeGeneralizedLoopLocalBuffer =
            backedges.empty()
                ? llvm::DenseMap<uint64_t, ValueByteReference>{}
                : extractLocalStackBuffer(backedges.front().buffer);
        if (discovery.valid && BBbackup[bb].sourceBlock) {
          activeGeneralizedLoopControlFieldState.valid = true;
          activeGeneralizedLoopControlFieldState.headerBlock = bb;
          activeGeneralizedLoopControlFieldState.canonicalSource =
              BBbackup[bb].sourceBlock;
          activeGeneralizedLoopControlFieldState.canonicalControl =
              discovery.canonicalControl;
          activeGeneralizedLoopControlFieldState.canonicalBuffer =
              BBbackup[bb].buffer;
          activeGeneralizedLoopControlFieldState.backedgeSources =
              std::move(discovery.backedgeSources);
          activeGeneralizedLoopControlFieldState.backedgeControls =
              std::move(discovery.backedgeControls);
          activeGeneralizedLoopControlFieldState.backedgeBuffers =
              std::move(discovery.backedgeBuffers);
          activeGeneralizedLoopControlFieldState.controlSlot =
              discovery.controlSlot;
          activeGeneralizedLoopControlFieldState.targetSlot =
              discovery.targetSlot;
          activeGeneralizedLoopControlFieldState.carriedSlots =
              std::move(discovery.carriedSlots);
          generalizedLoopControlFieldStates[bb] =
              activeGeneralizedLoopControlFieldState;
        }
      }
      if (this->liftProgressDiagEnabled && bb && bb->getName() == "bb_solved_const282") {
        auto valueToString = [](llvm::Value* value) {
          if (!value) {
            return std::string("<null>");
          }
          std::string text;
          llvm::raw_string_ostream os(text);
          value->print(os);
          return os.str();
        };
        constexpr std::array<const char*, 12> tracedNames = {
            "RAX", "RCX", "RDX", "RBX", "R8",  "R9",
            "R10", "R11", "R12", "R13", "R14", "R15"};
        constexpr std::array<size_t, 12> tracedIndices = {
            0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15};
        std::cout << "[diag] generalized regs bb=" << bb->getName().str();
        for (size_t i = 0; i < tracedIndices.size(); ++i) {
          size_t regIndex = tracedIndices[i];
          std::cout << " " << tracedNames[i] << " canonical="
                    << valueToString(BBbackup[bb].vec[regIndex]);
          for (size_t j = 0; j < backedges.size(); ++j) {
            std::cout << " backedge[" << j << "]="
                      << valueToString(backedges[j].vec[regIndex]);
          }
        }
        std::cout << "\n";
      }
      auto seedInvariantLocalQwords = [&](const backup_point& canonicalSnapshot,
                                          llvm::ArrayRef<backup_point> backedgeSnapshots) {
        std::set<uint64_t> seededQwordStarts;
        for (const auto& entry : activeGeneralizedLoopLocalBuffer) {
          uint64_t qwordStart = entry.first & ~0x7ULL;
          if (qwordStart > STACKP_VALUE - 0x100) {
            continue;
          }
          if (!seededQwordStarts.insert(qwordStart).second) {
            continue;
          }
          uint64_t canonicalValue = 0;
          if (!readConstantTrackedQword(canonicalSnapshot.buffer, qwordStart,
                                        canonicalValue)) {
            continue;
          }
          // All backedges must read the same concrete qword value for
          // the invariant to hold. Any mismatch disqualifies the qword.
          bool allMatch = true;
          for (const auto& be : backedgeSnapshots) {
            uint64_t beValue = 0;
            if (!readConstantTrackedQword(be.buffer, qwordStart, beValue) ||
                beValue != canonicalValue) {
              allMatch = false;
              break;
            }
          }
          if (!allMatch) {
            continue;
          }
          for (uint8_t i = 0; i < 8; ++i) {
            this->buffer[qwordStart + i] =
                activeGeneralizedLoopLocalBuffer[qwordStart + i];
          }
        }
      };
      seedInvariantLocalQwords(BBbackup[bb], backedges);
      return;
    }
    if (BBbackup.contains(bb)) {
      printvalue2("loading generalized backup");
      auto snapshot = make_generalized_loop_backup(
          bb, BBbackup[bb], llvm::ArrayRef<backup_point>{});
      restore_backup_point(snapshot);
    }
  }



  GeneralizedLoopControlFieldState* getMostRecentGeneralizedLoopState() {
    if (activeGeneralizedLoopControlFieldState.valid) {
      return &activeGeneralizedLoopControlFieldState;
    }
    if (generalizedLoopControlFieldStates.empty()) {
      return nullptr;
    }
    return &generalizedLoopControlFieldStates.begin()->second;
  }

  GeneralizedLoopControlFieldState* getGeneralizedLoopStateForHeader(
      llvm::BasicBlock* headerBlock) {
    if (!headerBlock) {
      return nullptr;
    }
    auto it = generalizedLoopControlFieldStates.find(headerBlock);
    if (it == generalizedLoopControlFieldStates.end() || !it->second.valid) {
      return nullptr;
    }
    return &it->second;
  }

  llvm::Value* retrieve_generalized_loop_local_value_impl(uint64_t startAddress,
                                                          uint8_t byteCount) {
    if (activeGeneralizedLoopLocalBuffer.empty()) {
      return nullptr;
    }
    return retrieveValueFromBufferSlice(activeGeneralizedLoopLocalBuffer, startAddress,
                                        byteCount);
  }
  llvm::Value* retrieve_generalized_loop_local_phi_address_value_impl(
      llvm::Value* loadOffset, uint8_t byteCount, LazyValue orgLoad) {
    (void)orgLoad;
    if (byteCount == 0) {
      return nullptr;
    }
    while (auto* castInst = llvm::dyn_cast<llvm::CastInst>(loadOffset)) {
      if (!castInst->getOperand(0)->getType()->isIntegerTy() ||
          !castInst->getType()->isIntegerTy()) {
        break;
      }
      loadOffset = castInst->getOperand(0);
    }
    auto* phi = llvm::dyn_cast<llvm::PHINode>(loadOffset);
    if (!phi || phi->getNumIncomingValues() < 2) {
      return nullptr;
    }
    auto* state = getGeneralizedLoopStateForHeader(phi->getParent());
    if (!state) {
      return nullptr;
    }

    auto resolveIncomingLocalValue = [&](llvm::Value* incomingAddress,
                                         llvm::BasicBlock* incomingBlock)
        -> llvm::Value* {
      auto* incomingCI = llvm::dyn_cast<llvm::ConstantInt>(incomingAddress);
      if (!incomingCI) {
        return nullptr;
      }
      const uint64_t address = incomingCI->getZExtValue();
      if (!this->isTrackedLocalStackAddress(address)) {
        return nullptr;
      }
      if (incomingBlock == state->canonicalSource) {
        return retrieveBufferedOrConcreteValue(state->canonicalBuffer, address,
                                              byteCount);
      }
      for (size_t i = 0; i < state->backedgeSources.size(); ++i) {
        if (incomingBlock == state->backedgeSources[i]) {
          return retrieveBufferedOrConcreteValue(state->backedgeBuffers[i],
                                                 address, byteCount);
        }
      }
      return nullptr;
    };


    llvm::SmallVector<std::pair<llvm::Value*, llvm::BasicBlock*>, 2> incomingLoads;
    llvm::Value* firstValue = nullptr;
    bool allSameValue = true;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* resolvedValue = resolveIncomingLocalValue(phi->getIncomingValue(i),
                                                      phi->getIncomingBlock(i));
      if (!resolvedValue) {
        return nullptr;
      }
      if (!firstValue) {
        firstValue = resolvedValue;
      } else if (resolvedValue != firstValue) {
        allSameValue = false;
      }
      incomingLoads.push_back({resolvedValue, phi->getIncomingBlock(i)});
    }
    if (incomingLoads.empty()) {
      return nullptr;
    }
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] generalized local-phi match block="

                << state->headerBlock->getName().str()
                << " byteCount=" << static_cast<unsigned>(byteCount);
      for (const auto& incoming : incomingLoads) {
        std::string valueText;
        llvm::raw_string_ostream valueStream(valueText);
        incoming.first->print(valueStream);
        std::cout << " incoming="
                  << (incoming.second ? incoming.second->getName().str()
                                      : std::string("<null>"))
                  << ":" << valueStream.str();
      }
      std::cout << "\n";
    }
    if (allSameValue) {
      return firstValue;
    }
    llvm::IRBuilder<> phiBuilder(state->headerBlock, state->headerBlock->begin());
    auto* phiLoad =
        phiBuilder.CreatePHI(incomingLoads.front().first->getType(),
                             incomingLoads.size(),
                             "generalized_local_phi_load");
    for (const auto& incoming : incomingLoads) {
      phiLoad->addIncoming(incoming.first, incoming.second);
    }
    return phiLoad;
  }

  llvm::Value* retrieve_generalized_loop_phi_address_value_impl(
      llvm::Value* loadOffset, uint8_t byteCount, LazyValue orgLoad) {
    (void)orgLoad;
    if (byteCount == 0) {
      return nullptr;
    }
    while (auto* castInst = llvm::dyn_cast<llvm::CastInst>(loadOffset)) {
      if (!castInst->getOperand(0)->getType()->isIntegerTy() ||
          !castInst->getType()->isIntegerTy()) {
        break;
      }
      loadOffset = castInst->getOperand(0);
    }
    int64_t displacement = 0;
    if (auto* binOp = llvm::dyn_cast<llvm::BinaryOperator>(loadOffset)) {
      auto* lhs = binOp->getOperand(0);
      auto* rhs = binOp->getOperand(1);
      auto* rhsCI = llvm::dyn_cast<llvm::ConstantInt>(rhs);
      auto* lhsCI = llvm::dyn_cast<llvm::ConstantInt>(lhs);
      if (rhsCI && (binOp->getOpcode() == llvm::Instruction::Add ||
                    binOp->getOpcode() == llvm::Instruction::Sub)) {
        loadOffset = lhs;
        displacement = rhsCI->getSExtValue();
        if (binOp->getOpcode() == llvm::Instruction::Sub) {
          displacement = -displacement;
        }
      } else if (lhsCI && binOp->getOpcode() == llvm::Instruction::Add) {
        loadOffset = rhs;
        displacement = lhsCI->getSExtValue();
      }
    }
    auto* phi = llvm::dyn_cast<llvm::PHINode>(loadOffset);
    if (!phi || phi->getNumIncomingValues() < 2) {
      return nullptr;
    }
    auto* state = getGeneralizedLoopStateForHeader(phi->getParent());
    if (!state) {
      return nullptr;
    }
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] generalized_phi_address current=0x" << std::hex
                << this->current_address << std::dec << " parent="
                << phi->getParent()->getName().str() << " activeSource="
                << (activeGeneralizedLoopEntrySourceBlock
                        ? activeGeneralizedLoopEntrySourceBlock->getName().str()
                        : std::string("<null>")) << "\n";
    }

    auto resolveIncomingValue = [&](llvm::Value* incomingAddress,
                                    llvm::BasicBlock* incomingBlock)
        -> llvm::Value* {
      auto* incomingCI = llvm::dyn_cast<llvm::ConstantInt>(incomingAddress);
      if (!incomingCI) {
        return nullptr;
      }
      const uint64_t address =
          static_cast<uint64_t>(incomingCI->getSExtValue() + displacement);
      if (incomingBlock == state->canonicalSource) {
        return retrieveBufferedOrConcreteValue(state->canonicalBuffer, address,
                                              byteCount);
      }
      for (size_t i = 0; i < state->backedgeSources.size(); ++i) {
        if (incomingBlock == state->backedgeSources[i]) {
          return retrieveBufferedOrConcreteValue(state->backedgeBuffers[i],
                                                 address, byteCount);
        }
      }
      return nullptr;
    };

    llvm::SmallVector<std::pair<llvm::Value*, llvm::BasicBlock*>, 2> incomingLoads;
    llvm::Value* firstValue = nullptr;
    bool allSameValue = true;
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      auto* resolvedValue =
          resolveIncomingValue(phi->getIncomingValue(i), phi->getIncomingBlock(i));
      if (!resolvedValue) {
        return nullptr;
      }
      if (!firstValue) {
        firstValue = resolvedValue;
      } else if (resolvedValue != firstValue) {
        allSameValue = false;
      }
      incomingLoads.push_back({resolvedValue, phi->getIncomingBlock(i)});
    }
    if (incomingLoads.empty()) {
      return nullptr;
    }
    if (allSameValue) {
      return firstValue;
    }
    llvm::IRBuilder<> phiBuilder(state->headerBlock, state->headerBlock->begin());
    auto* phiLoad =
        phiBuilder.CreatePHI(incomingLoads.front().first->getType(),
                             incomingLoads.size(),
                             "generalized_phi_load");
    for (const auto& incoming : incomingLoads) {
      phiLoad->addIncoming(incoming.first, incoming.second);
    }
    return phiLoad;
  }

  llvm::Value* retrieve_generalized_loop_control_slot_value_impl(
      uint64_t startAddress, uint8_t byteCount) {
    auto& state = activeGeneralizedLoopControlFieldState;
    if (!state.valid || startAddress != state.controlSlot ||
        byteCount == 0 || byteCount > 8) {
      return nullptr;
    }
    auto* canonicalValue = this->builder->getIntN(
        byteCount * 8, state.canonicalControl & llvm::maskTrailingOnes<uint64_t>(byteCount * 8));
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] control_slot current=0x" << std::hex
                << this->current_address << " start=0x" << startAddress
                << " canonical=0x" << state.canonicalControl << std::dec
                << " backedgeCount=" << state.backedgeControls.size()
                << " bytes=" << static_cast<unsigned>(byteCount) << "\n";
    }
    if (state.backedgeSources.empty()) {
      return canonicalValue;
    }
    // Build the canonical + N backedge values. If everything collapses to
    // a single value, skip phi construction.
    llvm::SmallVector<llvm::Value*, 2> backedgeValues;
    backedgeValues.reserve(state.backedgeControls.size());
    bool allSameAsCanonical = true;
    for (uint64_t be : state.backedgeControls) {
      auto* v = this->builder->getIntN(
          byteCount * 8, be & llvm::maskTrailingOnes<uint64_t>(byteCount * 8));
      if (v != canonicalValue) allSameAsCanonical = false;
      backedgeValues.push_back(v);
    }
    if (allSameAsCanonical) {
      return canonicalValue;
    }
    llvm::IRBuilder<> phiBuilder(state.headerBlock, state.headerBlock->begin());
    auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                     1 + backedgeValues.size(),
                                     "generalized_control_slot_phi");
    phi->addIncoming(canonicalValue, state.canonicalSource);
    for (size_t i = 0; i < backedgeValues.size(); ++i) {
      phi->addIncoming(backedgeValues[i], state.backedgeSources[i]);
    }
    return phi;
  }


  llvm::Value* retrieve_generalized_loop_target_slot_value_impl(
      uint64_t startAddress, uint8_t byteCount) {
    if (!activeGeneralizedLoopControlFieldState.valid || byteCount == 0) {
      return nullptr;
    }
    auto& state = activeGeneralizedLoopControlFieldState;

    // Check the legacy targetSlot first.
    if (startAddress == state.targetSlot) {
      auto* canonicalValue = retrieveBufferedOrConcreteValue(state.canonicalBuffer,
                                                             startAddress, byteCount);
      if (!canonicalValue) return nullptr;
      if (this->liftProgressDiagEnabled) {
        std::cout << "[diag] target_slot current=0x" << std::hex
                  << this->current_address << " start=0x" << startAddress
                  << std::dec << " bytes=" << static_cast<unsigned>(byteCount)
                  << " backedgeCount=" << state.backedgeBuffers.size() << "\n";
      }
      llvm::SmallVector<llvm::Value*, 2> backedgeValues;
      backedgeValues.reserve(state.backedgeBuffers.size());
      bool allSame = true;
      for (const auto& beBuf : state.backedgeBuffers) {
        auto* v = retrieveBufferedOrConcreteValue(beBuf, startAddress, byteCount);
        if (!v || v->getType() != canonicalValue->getType()) {
          return nullptr;
        }
        if (v != canonicalValue) allSame = false;
        backedgeValues.push_back(v);
      }
      if (state.backedgeSources.empty() || allSame) {
        return canonicalValue;
      }
      llvm::IRBuilder<> phiBuilder(state.headerBlock, state.headerBlock->begin());
      auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                       1 + backedgeValues.size(),
                                       "generalized_local_slot_phi");
      phi->addIncoming(canonicalValue, state.canonicalSource);
      for (size_t i = 0; i < backedgeValues.size(); ++i) {
        phi->addIncoming(backedgeValues[i], state.backedgeSources[i]);
      }
      return phi;
    }

    // Check additional carried slots (multi-slot extension).
    for (const auto& slot : state.carriedSlots) {
      if (slot.address != startAddress) continue;
      if (slot.backedgeValues.size() != state.backedgeSources.size()) continue;

      const uint64_t mask = llvm::maskTrailingOnes<uint64_t>(byteCount * 8);
      auto* canonicalValue = this->builder->getIntN(
          byteCount * 8, slot.canonicalValue & mask);

      llvm::SmallVector<llvm::Value*, 2> backedgeValues;
      bool allSame = true;
      for (uint64_t be : slot.backedgeValues) {
        auto* v = this->builder->getIntN(byteCount * 8, be & mask);
        if (v != canonicalValue) allSame = false;
        backedgeValues.push_back(v);
      }
      if (state.backedgeSources.empty() || allSame) {
        return canonicalValue;
      }
      llvm::IRBuilder<> phiBuilder(state.headerBlock, state.headerBlock->begin());
      auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                       1 + backedgeValues.size(),
                                       "generalized_carried_slot_phi");
      phi->addIncoming(canonicalValue, state.canonicalSource);
      for (size_t i = 0; i < backedgeValues.size(); ++i) {
        phi->addIncoming(backedgeValues[i], state.backedgeSources[i]);
      }
      return phi;
    }

    return nullptr;
  }

  llvm::Value* retrieve_generalized_loop_control_field_value_impl(
      llvm::Value* loadOffset, uint8_t byteCount, LazyValue orgLoad) {
    (void)orgLoad;
    if (!activeGeneralizedLoopControlFieldState.valid || byteCount == 0 ||
        this->builder->GetInsertBlock() !=
            activeGeneralizedLoopControlFieldState.headerBlock) {
      return nullptr;
    }
    uint64_t fieldOffset = 0;
    if (!matchGeneralizedLoopControlFieldAddress(loadOffset, fieldOffset)) {
      return nullptr;
    }
    auto& state = activeGeneralizedLoopControlFieldState;
    auto* canonicalValue = retrieveBufferedOrConcreteValue(
        state.canonicalBuffer, state.canonicalControl + fieldOffset, byteCount);
    if (!canonicalValue) return nullptr;
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] generalized control-field match block="
                << state.headerBlock->getName().str()
                << " fieldOffset=0x" << std::hex << fieldOffset
                << " canonical=0x" << (state.canonicalControl + fieldOffset)
                << std::dec << " bytes=" << static_cast<unsigned>(byteCount)
                << " backedgeCount=" << state.backedgeControls.size() << "\n";
    }
    llvm::SmallVector<llvm::Value*, 2> backedgeValues;
    backedgeValues.reserve(state.backedgeControls.size());
    bool allSame = true;
    for (size_t i = 0; i < state.backedgeControls.size(); ++i) {
      auto* v = retrieveBufferedOrConcreteValue(
          state.backedgeBuffers[i],
          state.backedgeControls[i] + fieldOffset, byteCount);
      if (!v || v->getType() != canonicalValue->getType()) {
        return nullptr;
      }
      if (v != canonicalValue) allSame = false;
      backedgeValues.push_back(v);
    }
    if (state.backedgeSources.empty() || allSame) {
      return canonicalValue;
    }
    llvm::IRBuilder<> phiBuilder(state.headerBlock, state.headerBlock->begin());
    auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(),
                                     1 + backedgeValues.size(),
                                     "loop_control_field_phi");
    phi->addIncoming(canonicalValue, state.canonicalSource);
    for (size_t i = 0; i < backedgeValues.size(); ++i) {
      phi->addIncoming(backedgeValues[i], state.backedgeSources[i]);
    }
    return phi;
  }
  void migrate_generalized_loop_block_impl(BasicBlock* oldBlock,
                                           BasicBlock* newBlock) {
    if (oldBlock == newBlock) {
      return;
    }
    if (generalizedLoopRegisterPhis.contains(oldBlock) &&
        !generalizedLoopRegisterPhis.contains(newBlock)) {
      generalizedLoopRegisterPhis[newBlock] = generalizedLoopRegisterPhis[oldBlock];
    }
    if (generalizedLoopFlagPhis.contains(oldBlock) &&
        !generalizedLoopFlagPhis.contains(newBlock)) {
      generalizedLoopFlagPhis[newBlock] = generalizedLoopFlagPhis[oldBlock];
    }
    if (BBbackup.contains(oldBlock) && !BBbackup.contains(newBlock)) {
      BBbackup[newBlock] = BBbackup[oldBlock];
    }
    if (generalizedLoopBackedgeBackup.contains(oldBlock) &&
        !generalizedLoopBackedgeBackup.contains(newBlock)) {
      generalizedLoopBackedgeBackup[newBlock] =
          generalizedLoopBackedgeBackup[oldBlock];
    }
    if (generalizedLoopControlFieldStates.contains(oldBlock) &&
        !generalizedLoopControlFieldStates.contains(newBlock)) {
      generalizedLoopControlFieldStates[newBlock] =
          generalizedLoopControlFieldStates[oldBlock];
      generalizedLoopControlFieldStates[newBlock].headerBlock = newBlock;
    }
  }

  void record_generalized_loop_backedge_impl(BasicBlock* bb) {
    auto* sourceBlock = this->builder->GetInsertBlock();
    if (!bb || !sourceBlock) {
      return;
    }

    auto regIt = generalizedLoopRegisterPhis.find(bb);
    if (regIt != generalizedLoopRegisterPhis.end()) {
      for (size_t i = 0; i < REGISTER_COUNT; ++i) {
        auto* phi = regIt->second[i];
        if (!phi || !vec[i] || phi->getType() != vec[i]->getType() ||
            phi->getParent() != bb ||
            phi->getBasicBlockIndex(sourceBlock) >= 0) {
          continue;
        }
        phi->addIncoming(vec[i], sourceBlock);
      }
    }


    auto flagIt = generalizedLoopFlagPhis.find(bb);
    if (flagIt != generalizedLoopFlagPhis.end()) {
      for (size_t i = 0; i < FLAGS_END; ++i) {
        auto* phi = flagIt->second[i];
        if (!phi || !vecflag[i] || phi->getType() != vecflag[i]->getType() ||
            phi->getParent() != bb ||
            phi->getBasicBlockIndex(sourceBlock) >= 0) {
          continue;
        }
        phi->addIncoming(vecflag[i], sourceBlock);
      }
    }
    auto stateIt = generalizedLoopControlFieldStates.find(bb);
    if (stateIt == generalizedLoopControlFieldStates.end() ||
        !stateIt->second.valid) {
      return;
    }
    auto& sources = stateIt->second.backedgeSources;
    auto& controls = stateIt->second.backedgeControls;
    auto& buffers = stateIt->second.backedgeBuffers;

    if (sources.size() == 1) {
      // 2-way loop: preserve the original rotation semantics - move the
      // current backedge into canonical and install the new body source
      // as the single backedge. This matches the reference Themida flow
      // where body exploration rolls the control cursor forward.
      auto* existingBackedgeSource = sources.front();
      if (!existingBackedgeSource || sourceBlock == existingBackedgeSource) {
        return;
      }
      auto* currentControlValue =
          retrieveContiguousBufferedValue(this->buffer, stateIt->second.controlSlot, 8);
      uint64_t rolledBackedgeControl = 0;
      if (!currentControlValue ||
          !evaluateConcreteGeneralizedLoopInt(currentControlValue,
                                              existingBackedgeSource,
                                              rolledBackedgeControl) ||
          rolledBackedgeControl == controls.front()) {
        return;
      }
      auto previousBackedgeSource = existingBackedgeSource;
      auto previousBackedgeControl = controls.front();
      auto previousBackedgeBuffer = buffers.front();
      stateIt->second.canonicalSource = previousBackedgeSource;
      stateIt->second.canonicalControl = previousBackedgeControl;
      stateIt->second.canonicalBuffer = previousBackedgeBuffer;
      sources.front() = sourceBlock;
      controls.front() = rolledBackedgeControl;
      buffers.front() = this->buffer;
      // Rotate carried slots alongside the primary control slot.
      for (auto& carried : stateIt->second.carriedSlots) {
        if (carried.backedgeValues.size() != 1) continue;
        uint64_t newCarriedValue = 0;
        if (readConstantTrackedQword(this->buffer, carried.address, newCarriedValue)) {
          carried.canonicalValue = carried.backedgeValues.front();
          carried.backedgeValues.front() = newCarriedValue;
        }
      }
      if (bb == activeGeneralizedLoopControlFieldState.headerBlock) {
        activeGeneralizedLoopControlFieldState = stateIt->second;
        activeGeneralizedLoopEntrySourceBlock = sourceBlock;
        activeGeneralizedLoopLocalBuffer = extractLocalStackBuffer(
            activeGeneralizedLoopControlFieldState.backedgeBuffers.front());
      }
      if (this->liftProgressDiagEnabled) {
        std::cout << "[diag] roll_generalized_backedge bb=" << bb->getName().str()
                  << " canonical=0x" << std::hex
                  << stateIt->second.canonicalControl << " backedge=0x"
                  << controls.front() << std::dec
                  << " source=" << sourceBlock->getName().str() << "\n";
      }
      return;
    }

    // Multi-way loop (size > 1): append-or-update the body source to the
    // backedge list. Each distinct body block contributes at most one
    // entry (dedup by sourceBlock). This preserves the original N
    // backedges and records the body's rolled state alongside them;
    // unbounded growth is prevented by the per-sourceBlock dedup.
    // Rotation (promoting a backedge to canonical) is undefined for
    // multi-way - no single backedge is "the" one to promote.
    if (sourceBlock == stateIt->second.canonicalSource) {
      return;
    }
    auto* currentControlValue =
        retrieveContiguousBufferedValue(this->buffer, stateIt->second.controlSlot, 8);
    uint64_t newControl = 0;
    if (!currentControlValue ||
        !evaluateConcreteGeneralizedLoopInt(currentControlValue, sourceBlock,
                                            newControl)) {
      return;
    }
    bool mutated = false;
    bool isNew = true;
    for (size_t i = 0; i < sources.size(); ++i) {
      if (sources[i] == sourceBlock) {
        isNew = false;
        if (controls[i] == newControl) {
          return;  // no progress; nothing to record
        }
        controls[i] = newControl;
        buffers[i] = this->buffer;
        // Update carried slots for this backedge index.
        for (auto& carried : stateIt->second.carriedSlots) {
          if (i < carried.backedgeValues.size()) {
            uint64_t newVal = 0;
            if (readConstantTrackedQword(this->buffer, carried.address, newVal)) {
              carried.backedgeValues[i] = newVal;
            }
          }
        }
        mutated = true;
        break;
      }
    }
    if (isNew) {
      sources.push_back(sourceBlock);
      controls.push_back(newControl);
      buffers.push_back(this->buffer);
      // Append carried slot values for the new backedge.
      for (auto& carried : stateIt->second.carriedSlots) {
        uint64_t newVal = 0;
        if (readConstantTrackedQword(this->buffer, carried.address, newVal)) {
          carried.backedgeValues.push_back(newVal);
        } else {
          // Keep vectors aligned: push canonical as fallback.
          carried.backedgeValues.push_back(carried.canonicalValue);
        }
      }
      mutated = true;
    }
    if (mutated && bb == activeGeneralizedLoopControlFieldState.headerBlock) {
      activeGeneralizedLoopControlFieldState = stateIt->second;
    }
    if (mutated && this->liftProgressDiagEnabled) {
      std::cout << "[diag] roll_generalized_backedge_multiway bb="
                << bb->getName().str()
                << " backedgeCount=" << sources.size()
                << " source=" << sourceBlock->getName().str() << std::dec
                << "\n";
    }
  }

  void createFunction_impl() {
    std::vector<llvm::Type*> argTypes;
    for (size_t i = 0; i < 16; ++i) {
      argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    }

    argTypes.push_back(llvm::PointerType::get(this->context, 0));
    argTypes.push_back(llvm::PointerType::get(this->context, 0)); // memory

    for (size_t i = 0; i < 16; ++i) {
      argTypes.push_back(llvm::Type::getInt128Ty(this->context));
    }

    auto functionType = llvm::FunctionType::get(
        llvm::Type::getInt64Ty(this->context), argTypes, 0);

    const std::string function_name = "main";
    this->fnc =
        llvm::Function::Create(functionType, llvm::Function::ExternalLinkage,
                               function_name.c_str(), this->M);
  }

  void InitRegisters_impl() {
    constexpr std::array<Register, 16> gprOrder = {
        Register::RAX, Register::RCX, Register::RDX, Register::RBX,
        Register::RSP, Register::RBP, Register::RSI, Register::RDI,
        Register::R8,  Register::R9,  Register::R10, Register::R11,
        Register::R12, Register::R13, Register::R14, Register::R15,
    };

    auto argIt = this->fnc->arg_begin();
    for (auto reg : gprOrder) {
      auto* arg = &*argIt++;
      arg->setName(magic_enum::enum_name(reg));
      this->SetRegisterValue(reg, arg);
    }

    auto* eipArg = &*argIt++;
    eipArg->setName("EIP");
    auto* ripValue = eipArg->getType()->isPointerTy()
                         ? this->builder->CreatePtrToInt(
                               eipArg, llvm::Type::getInt64Ty(this->context), "rip.arg")
                         : this->builder->CreateZExtOrTrunc(
                               eipArg, llvm::Type::getInt64Ty(this->context), "rip.arg");
    this->SetRegisterValue(Register::RIP, ripValue);
    auto* memoryArg = &*argIt++;
    memoryArg->setName("memory");
    this->memoryAlloc = memoryArg;

    for (uint8_t i = 0; i < 16; ++i) {
      auto xmmReg =
          static_cast<Register>(static_cast<int>(Register::XMM0) + i);
      auto* xmmArg = &*argIt++;
      xmmArg->setName(magic_enum::enum_name(xmmReg));
      this->SetRegisterValue(xmmReg, xmmArg);
    }
    // printvalue(GetRegisterValue(Register::RAX));

    LLVMContext& context = this->builder->getContext();
    auto zero = ConstantInt::getSigned(Type::getInt1Ty(context), 0);
    auto one = ConstantInt::getSigned(Type::getInt1Ty(context), 1);
    auto two = ConstantInt::getSigned(Type::getInt1Ty(context), 2);

    this->FlagList[FLAG_CF].set(zero);
    this->FlagList[FLAG_PF].set(zero);
    this->FlagList[FLAG_AF].set(zero);
    this->FlagList[FLAG_ZF].set(zero);
    this->FlagList[FLAG_SF].set(zero);
    this->FlagList[FLAG_TF].set(zero);
    this->FlagList[FLAG_IF].set(one);
    this->FlagList[FLAG_DF].set(zero);
    this->FlagList[FLAG_OF].set(zero);

    this->FlagList[FLAG_RESERVED1].set(one);
    this->SetRegisterValue(Register::RFLAGS, two);

    // auto value =
    //     cast<Value>(ConstantInt::getSigned(Type::getInt64Ty(context),
    //     rip));

    // auto new_rip = createAddFolder(zero, value);

    // SetRegisterValue(Register::RIP, new_rip);

    auto stackvalue = cast<Value>(
        ConstantInt::getSigned(Type::getInt64Ty(context), STACKP_VALUE));

    this->SetRegisterValue(Register::RSP, stackvalue);

    return;
  }
};
#endif