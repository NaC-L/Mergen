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
                          const char* name, llvm::PHINode*& phiOut)
        -> llvm::Value* {
      if (!canonicalValue || !backedgeValue ||
          canonicalValue->getType() != backedgeValue->getType() ||
          canonicalValue == backedgeValue) {
        return backedgeValue;
      }
      auto* phi = phiBuilder.CreatePHI(canonicalValue->getType(), 2, name);
      phi->addIncoming(canonicalValue, canonicalSource);
      phi->addIncoming(llvm::UndefValue::get(backedgeValue->getType()),
                       backedgeSource);
      phiOut = phi;
      return phi;
    };

    for (size_t i = 0; i < REGISTER_COUNT; ++i) {
      generalized.vec[i] = mergeValue(canonical.vec[i], source.vec[i],
                                      "loop_reg_phi", registerPhis[i]);
    }
    for (size_t i = 0; i < FLAGS_END; ++i) {
      generalized.vecflag[i] =
          mergeValue(canonical.vecflag[i], source.vecflag[i], "loop_flag_phi",
                     flagPhis[i]);
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
      restore_backup_point(BBbackup[bb]);
    }
  }

  void load_generalized_backup_impl(BasicBlock* bb) {
    activeGeneralizedLoopLocalBuffer.clear();
    if (generalizedLoopBackedgeBackup.contains(bb) && BBbackup.contains(bb)) {
      printvalue2("loading generalized backup");
      auto snapshot =
          make_generalized_loop_backup(bb, BBbackup[bb],
                                       generalizedLoopBackedgeBackup[bb]);
      restore_backup_point(snapshot);
      activeGeneralizedLoopLocalBuffer =
          extractLocalStackBuffer(generalizedLoopBackedgeBackup[bb].buffer);
      auto seedInvariantLocalQwords = [&](const backup_point& canonicalSnapshot,
                                          const backup_point& backedgeSnapshot) {
        std::set<uint64_t> seededQwordStarts;
        auto readConstantQword = [&](const llvm::DenseMap<uint64_t, ValueByteReference>& src,
                                     uint64_t qwordStart, uint64_t& out) {
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
            auto byteValue =
                ci->getValue().lshr(it->second.byteOffset * 8).trunc(8);
            combined |= byteValue.zext(64).shl(i * 8);
          }
          out = combined.getZExtValue();
          return true;
        };

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
          if (!readConstantQword(canonicalSnapshot.buffer, qwordStart, canonicalValue) ||
              !readConstantQword(backedgeSnapshot.buffer, qwordStart, backedgeValue) ||
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

  llvm::Value* retrieve_generalized_loop_local_value_impl(uint64_t startAddress,
                                                          uint8_t byteCount) {
    if (activeGeneralizedLoopLocalBuffer.empty()) {
      return nullptr;
    }
    auto firstIt = activeGeneralizedLoopLocalBuffer.find(startAddress);
    if (firstIt == activeGeneralizedLoopLocalBuffer.end() || !firstIt->second.value) {
      return nullptr;
    }

    bool contiguousSingleValue = true;
    auto* sharedValue = firstIt->second.value;
    uint8_t firstByteOffset = firstIt->second.byteOffset;
    for (uint8_t i = 0; i < byteCount; ++i) {
      auto it = activeGeneralizedLoopLocalBuffer.find(startAddress + i);
      if (it == activeGeneralizedLoopLocalBuffer.end() || !it->second.value) {
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
      auto it = activeGeneralizedLoopLocalBuffer.find(startAddress + i);
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