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
  llvm::DenseMap<BasicBlock*, backup_point> generalizedLoopBackedgeBackup;

  llvm::DenseMap<BasicBlock*, std::array<llvm::PHINode*, REGISTER_COUNT>>
      generalizedLoopRegisterPhis;
  llvm::DenseMap<BasicBlock*, std::array<llvm::PHINode*, FLAGS_END>>
      generalizedLoopFlagPhis;
  llvm::DenseMap<uint64_t, ValueByteReference> activeGeneralizedLoopLocalBuffer;
  struct GeneralizedLoopControlFieldState {
    bool valid = false;
    llvm::BasicBlock* headerBlock = nullptr;
    llvm::BasicBlock* canonicalSource = nullptr;
    llvm::BasicBlock* backedgeSource = nullptr;
    uint64_t canonicalControl = 0;
    uint64_t backedgeControl = 0;
    llvm::DenseMap<uint64_t, ValueByteReference> canonicalBuffer;
    llvm::DenseMap<uint64_t, ValueByteReference> backedgeBuffer;
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
    activeGeneralizedLoopControlFieldState.backedgeSource = nullptr;
    activeGeneralizedLoopControlFieldState.canonicalControl = 0;
    activeGeneralizedLoopControlFieldState.backedgeControl = 0;
    activeGeneralizedLoopControlFieldState.canonicalBuffer.clear();
    activeGeneralizedLoopControlFieldState.backedgeBuffer.clear();
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
    if (!offsetCI || offsetCI->getZExtValue() != kThemidaControlCursorSlot) {
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


  bool shouldPreserveGeneralizedBackedgeRegisterIndex(size_t index) const {
    switch (index) {
    case 1:  // RCX
    case 4:  // RSP
    case 7:  // hot loop_reg_phi289 lane
    case 9:  // hot loop_reg_phi291 lane
    case 10: // loop_reg_phi292 / R10 lane
    case 12: // hot loop_reg_phi294 lane
    case 14: // hot loop_reg_phi296 lane
      return true;
    default:
      return false;
    }
  }

  backup_point make_generalized_loop_backup(BasicBlock* bb,
                                            const backup_point& canonical,
                                            const backup_point& source) {
    backup_point generalized = source;
    llvm::DenseMap<uint64_t, ValueByteReference> filteredBuffer;
    filteredBuffer.reserve(source.buffer.size());
    for (const auto& entry : source.buffer) {
      if (!this->isTrackedLocalStackAddress(entry.first)) {
        filteredBuffer[entry.first] = entry.second;
      }
    }
    generalized.buffer = std::move(filteredBuffer);
    generalized.cache = InstructionCache();
    generalized.assumptions.clear();

    auto* canonicalSource = canonical.sourceBlock;
    auto* backedgeSource = source.sourceBlock;
    if (!bb || !canonicalSource || !backedgeSource ||
        canonicalSource == backedgeSource) {
      return generalized;
    }

    std::array<llvm::PHINode*, REGISTER_COUNT> registerPhis{};
    std::array<llvm::PHINode*, FLAGS_END> flagPhis{};
    llvm::IRBuilder<> phiBuilder(bb, bb->begin());
    auto mergeValue = [&](llvm::Value* canonicalValue, llvm::Value* backedgeValue,
                          const char* name, llvm::PHINode*& phiOut,
                          bool widenFirstBackedge)
        -> llvm::Value* {
      if (!canonicalValue || !backedgeValue ||
          canonicalValue->getType() != backedgeValue->getType() ||
          canonicalValue == backedgeValue) {
        return backedgeValue;
      }
      auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(), 2, name);
      phi->addIncoming(canonicalValue, canonicalSource);
      phi->addIncoming(widenFirstBackedge
                           ? llvm::UndefValue::get(backedgeValue->getType())
                           : backedgeValue,
                       backedgeSource);
      phiOut = phi;
      return phi;
    };
    constexpr std::array<Register, 16> gprOrder = {
        Register::RAX, Register::RCX, Register::RDX, Register::RBX,
        Register::RSP, Register::RBP, Register::RSI, Register::RDI,
        Register::R8,  Register::R9,  Register::R10, Register::R11,
        Register::R12, Register::R13, Register::R14, Register::R15,
    };

    for (size_t i = 0; i < REGISTER_COUNT; ++i) {
      const bool widenFirstBackedge =
          !shouldPreserveGeneralizedBackedgeRegisterIndex(i);
      generalized.vec[i] = mergeValue(canonical.vec[i], source.vec[i],
                                      "loop_reg_phi", registerPhis[i],
                                      widenFirstBackedge);
    }
    for (size_t i = 0; i < FLAGS_END; ++i) {
      generalized.vecflag[i] =
          mergeValue(canonical.vecflag[i], source.vecflag[i], "loop_flag_phi",
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
      generalizedLoopBackedgeBackup[bb] = std::move(snapshot);
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

  void load_generalized_backup_impl(BasicBlock* bb) {
    activeGeneralizedLoopLocalBuffer.clear();
    clearGeneralizedLoopControlFieldState();
    if (generalizedLoopBackedgeBackup.contains(bb) && BBbackup.contains(bb)) {
      printvalue2("loading generalized backup");
      auto snapshot =
          make_generalized_loop_backup(bb, BBbackup[bb],
                                       generalizedLoopBackedgeBackup[bb]);
      if (this->liftProgressDiagEnabled) {
        auto formatHex = [](uint64_t value) {
          std::ostringstream os;
          os << "0x" << std::hex << std::uppercase << value;
          return os.str();
        };
        uint64_t canonicalControl = 0;
        uint64_t backedgeControl = 0;
        const bool hasCanonicalControl = readConstantTrackedQword(
            BBbackup[bb].buffer, kThemidaControlCursorSlot, canonicalControl);
        const bool hasBackedgeControl =
            readConstantTrackedQword(generalizedLoopBackedgeBackup[bb].buffer,
                                     kThemidaControlCursorSlot, backedgeControl);
        std::cout << "[diag] load_generalized_backup bb=" << bb->getName().str()
                  << " sourceCanonical="
                  << (BBbackup[bb].sourceBlock
                          ? BBbackup[bb].sourceBlock->getName().str()
                          : std::string("<null>"))
                  << " sourceBackedge="
                  << (generalizedLoopBackedgeBackup[bb].sourceBlock
                          ? generalizedLoopBackedgeBackup[bb].sourceBlock->getName().str()
                          : std::string("<null>"))
                  << " backedge14fca0="
                  << (generalizedLoopBackedgeBackup[bb].buffer.contains(1375392) ? 1 : 0)
                  << " backedge14fca8="
                  << (generalizedLoopBackedgeBackup[bb].buffer.contains(1375400) ? 1 : 0)
                  << " backedge14fcb0="
                  << (generalizedLoopBackedgeBackup[bb].buffer.contains(1375408) ? 1 : 0)
                  << " canonicalControl="
                  << (hasCanonicalControl ? formatHex(canonicalControl)
                                          : std::string("na"))
                  << " backedgeControl="
                  << (hasBackedgeControl ? formatHex(backedgeControl)
                                         : std::string("na"))
                  << "\n";
      }
      restore_backup_point(snapshot);
      auto storedStateIt = generalizedLoopControlFieldStates.find(bb);
      if (storedStateIt != generalizedLoopControlFieldStates.end() &&
          storedStateIt->second.valid) {
        activeGeneralizedLoopControlFieldState = storedStateIt->second;
        activeGeneralizedLoopEntrySourceBlock =
            activeGeneralizedLoopControlFieldState.backedgeSource;
        activeGeneralizedLoopLocalBuffer = extractLocalStackBuffer(
            activeGeneralizedLoopControlFieldState.backedgeBuffer);
      } else {
        activeGeneralizedLoopEntrySourceBlock =
            generalizedLoopBackedgeBackup[bb].sourceBlock;
        uint64_t canonicalControl = 0;
        uint64_t backedgeControl = 0;
        activeGeneralizedLoopLocalBuffer =
            extractLocalStackBuffer(generalizedLoopBackedgeBackup[bb].buffer);
        if (readConstantTrackedQword(BBbackup[bb].buffer, kThemidaControlCursorSlot,
                                     canonicalControl) &&
            readConstantTrackedQword(generalizedLoopBackedgeBackup[bb].buffer,
                                     kThemidaControlCursorSlot, backedgeControl) &&
            canonicalControl != backedgeControl && BBbackup[bb].sourceBlock &&
            generalizedLoopBackedgeBackup[bb].sourceBlock &&
            BBbackup[bb].sourceBlock != generalizedLoopBackedgeBackup[bb].sourceBlock) {
          activeGeneralizedLoopControlFieldState.valid = true;
          activeGeneralizedLoopControlFieldState.headerBlock = bb;
          activeGeneralizedLoopControlFieldState.canonicalSource =
              BBbackup[bb].sourceBlock;
          activeGeneralizedLoopControlFieldState.backedgeSource =
              generalizedLoopBackedgeBackup[bb].sourceBlock;
          activeGeneralizedLoopControlFieldState.canonicalControl =
              canonicalControl;
          activeGeneralizedLoopControlFieldState.backedgeControl =
              backedgeControl;
          activeGeneralizedLoopControlFieldState.canonicalBuffer = BBbackup[bb].buffer;
          activeGeneralizedLoopControlFieldState.backedgeBuffer =
              generalizedLoopBackedgeBackup[bb].buffer;
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
                    << valueToString(BBbackup[bb].vec[regIndex])
                    << " backedge="
                    << valueToString(generalizedLoopBackedgeBackup[bb].vec[regIndex]);
        }
        std::cout << "\n";
      }
      auto seedInvariantLocalQwords = [&](const backup_point& canonicalSnapshot,
                                          const backup_point& backedgeSnapshot) {
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
          uint64_t backedgeValue = 0;
          if (!readConstantTrackedQword(canonicalSnapshot.buffer, qwordStart,
                                        canonicalValue) ||
              !readConstantTrackedQword(backedgeSnapshot.buffer, qwordStart,
                                        backedgeValue) ||
              canonicalValue != backedgeValue) {
            continue;
          }
          for (uint8_t i = 0; i < 8; ++i) {
            this->buffer[qwordStart + i] =
                activeGeneralizedLoopLocalBuffer[qwordStart + i];
          }
        }
      };
      seedInvariantLocalQwords(BBbackup[bb], generalizedLoopBackedgeBackup[bb]);
      return;
    }
    if (BBbackup.contains(bb)) {
      printvalue2("loading generalized backup");
      auto snapshot = make_generalized_loop_backup(bb, BBbackup[bb], BBbackup[bb]);
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
    if (!phi || phi->getNumIncomingValues() != 2) {
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
      if (incomingBlock == state->backedgeSource) {
        return retrieveBufferedOrConcreteValue(state->backedgeBuffer, address,
                                              byteCount);
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
    if (!phi || phi->getNumIncomingValues() != 2) {
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
      if (incomingBlock == state->backedgeSource) {
        return retrieveBufferedOrConcreteValue(state->backedgeBuffer, address,
                                              byteCount);
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
    if (!state.valid || startAddress != this->kThemidaControlCursorSlot ||
        byteCount == 0 || byteCount > 8) {
      return nullptr;
    }
    auto* canonicalValue = this->builder->getIntN(
        byteCount * 8, state.canonicalControl & llvm::maskTrailingOnes<uint64_t>(byteCount * 8));
    auto* backedgeValue = this->builder->getIntN(
        byteCount * 8, state.backedgeControl & llvm::maskTrailingOnes<uint64_t>(byteCount * 8));
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] control_slot current=0x" << std::hex
                << this->current_address << " start=0x" << startAddress
                << " canonical=0x" << state.canonicalControl
                << " backedge=0x" << state.backedgeControl << std::dec
                << " bytes=" << static_cast<unsigned>(byteCount) << "\n";
    }
    if (canonicalValue == backedgeValue) {
      return canonicalValue;
    }
    llvm::IRBuilder<> phiBuilder(state.headerBlock, state.headerBlock->begin());
    auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(), 2,
                                     "generalized_control_slot_phi");
    phi->addIncoming(canonicalValue, state.canonicalSource);
    phi->addIncoming(backedgeValue, state.backedgeSource);
    return phi;
  }


  llvm::Value* retrieve_generalized_loop_target_slot_value_impl(
      uint64_t startAddress, uint8_t byteCount) {
    if (!activeGeneralizedLoopControlFieldState.valid ||
        startAddress != this->kThemidaLoopCarriedSlot || byteCount == 0) {
      return nullptr;
    }
    auto* canonicalValue = retrieveBufferedOrConcreteValue(
        activeGeneralizedLoopControlFieldState.canonicalBuffer, startAddress,
        byteCount);
    auto* backedgeValue = retrieveBufferedOrConcreteValue(
        activeGeneralizedLoopControlFieldState.backedgeBuffer, startAddress,
        byteCount);
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] target_slot current=0x" << std::hex
                << this->current_address << " start=0x" << startAddress
                << std::dec << " bytes=" << static_cast<unsigned>(byteCount)
                << "\n";
    }
    if (!canonicalValue || !backedgeValue ||
        canonicalValue->getType() != backedgeValue->getType()) {
      return nullptr;
    }
    if (canonicalValue == backedgeValue) {
      return canonicalValue;
    }
    llvm::IRBuilder<> phiBuilder(activeGeneralizedLoopControlFieldState.headerBlock,
                                 activeGeneralizedLoopControlFieldState.headerBlock
                                     ->begin());
    auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(), 2,
                                     "generalized_local_slot_phi");
    phi->addIncoming(canonicalValue,
                     activeGeneralizedLoopControlFieldState.canonicalSource);
    phi->addIncoming(backedgeValue,
                     activeGeneralizedLoopControlFieldState.backedgeSource);
    return phi;
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
    auto* canonicalValue = retrieveBufferedOrConcreteValue(
        activeGeneralizedLoopControlFieldState.canonicalBuffer,
        activeGeneralizedLoopControlFieldState.canonicalControl + fieldOffset,
        byteCount);
    auto* backedgeValue = retrieveBufferedOrConcreteValue(
        activeGeneralizedLoopControlFieldState.backedgeBuffer,
        activeGeneralizedLoopControlFieldState.backedgeControl + fieldOffset,
        byteCount);
    if (!canonicalValue || !backedgeValue ||
        canonicalValue->getType() != backedgeValue->getType()) {
      return nullptr;
    }
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] generalized control-field match block="
                << activeGeneralizedLoopControlFieldState.headerBlock->getName().str()
                << " fieldOffset=0x" << std::hex << fieldOffset
                << " canonical=0x"
                << (activeGeneralizedLoopControlFieldState.canonicalControl +
                    fieldOffset)
                << " backedge=0x"
                << (activeGeneralizedLoopControlFieldState.backedgeControl +
                    fieldOffset)
                << std::dec << " bytes=" << static_cast<unsigned>(byteCount)
                << "\n";
    }
    if (canonicalValue == backedgeValue) {
      return canonicalValue;
    }
    llvm::IRBuilder<> phiBuilder(activeGeneralizedLoopControlFieldState.headerBlock,
                                 activeGeneralizedLoopControlFieldState.headerBlock
                                     ->begin());
    auto* phi =
        phiBuilder.CreatePHI(canonicalValue->getType(), 2, "loop_control_field_phi");
    phi->addIncoming(canonicalValue,
                     activeGeneralizedLoopControlFieldState.canonicalSource);
    phi->addIncoming(backedgeValue,
                     activeGeneralizedLoopControlFieldState.backedgeSource);
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
        !stateIt->second.valid || !stateIt->second.backedgeSource ||
        sourceBlock == stateIt->second.backedgeSource) {
      return;
    }
    auto* currentControlValue =
        retrieveContiguousBufferedValue(this->buffer, kThemidaControlCursorSlot, 8);
    uint64_t rolledBackedgeControl = 0;
    if (!currentControlValue ||
        !evaluateConcreteGeneralizedLoopInt(currentControlValue,
                                            stateIt->second.backedgeSource,
                                            rolledBackedgeControl) ||
        rolledBackedgeControl == stateIt->second.backedgeControl) {
      return;
    }
    auto previousBackedgeSource = stateIt->second.backedgeSource;
    auto previousBackedgeControl = stateIt->second.backedgeControl;
    auto previousBackedgeBuffer = stateIt->second.backedgeBuffer;
    stateIt->second.canonicalSource = previousBackedgeSource;
    stateIt->second.canonicalControl = previousBackedgeControl;
    stateIt->second.canonicalBuffer = previousBackedgeBuffer;
    stateIt->second.backedgeSource = sourceBlock;
    stateIt->second.backedgeControl = rolledBackedgeControl;
    stateIt->second.backedgeBuffer = this->buffer;
    if (bb == activeGeneralizedLoopControlFieldState.headerBlock) {
      activeGeneralizedLoopControlFieldState = stateIt->second;
      activeGeneralizedLoopEntrySourceBlock = sourceBlock;
      activeGeneralizedLoopLocalBuffer =
          extractLocalStackBuffer(activeGeneralizedLoopControlFieldState.backedgeBuffer);
    }
    if (this->liftProgressDiagEnabled) {
      std::cout << "[diag] roll_generalized_backedge bb=" << bb->getName().str()
                << " canonical=0x" << std::hex
                << stateIt->second.canonicalControl << " backedge=0x"
                << stateIt->second.backedgeControl << std::dec
                << " source=" << sourceBlock->getName().str() << "\n";
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