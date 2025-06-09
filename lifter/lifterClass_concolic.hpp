#ifndef LIFTERCLASS_CONCRETE_H
#define LIFTERCLASS_CONCRETE_H
#include "CommonDisassembler.hpp"
#include "RegisterManager.hpp"
#include "icedDisassembler.hpp"
#include "icedDisassembler_mnemonics.h"
#include "icedDisassembler_registers.h"
#include "lifterClass.hpp"
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
    REGISTER_COUNT = RFLAGS_ // Total number of registers
  };
  std::array<llvm::Value*, REGISTER_COUNT> vec;
  std::array<llvm::Value*, FLAGS_END> vecflag;

  int getRegisterIndex(Register key) const {

    switch (key) {
    case Register::RIP: {
      return RIP_;
    }
    case Register::RFLAGS: {
      return RFLAGS_;
    }
    default: {
      assert(((key >= Register::RAX && key <= Register::R15) ||
              key == Register::EIP || key == Register::RIP) &&
             "Key must be between RAX and R15");

      return (static_cast<int>(key) - static_cast<int>(Register::RAX));
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

    bool operator==(const backup_point& other) const {
      if (buffer != other.buffer)
        return false;
      return vec == other.vec && vecflag == other.vecflag;
    }

    backup_point(backup_point& other)
        : vec(other.vec), vecflag(other.vecflag), buffer(other.buffer),
          cache(other.cache), assumptions(other.assumptions), ct(other.ct){};

    backup_point(backup_point&& other) noexcept
        : vec(std::move(other.vec)), vecflag(std::move(other.vecflag)),
          buffer(std::move(other.buffer)), cache(std::move(other.cache)),
          assumptions(other.assumptions), ct(other.ct) {}

    backup_point(std::array<llvm::Value*, REGISTER_COUNT> vec,
                 std::array<llvm::Value*, FLAGS_END> vecflag,
                 llvm::DenseMap<uint64_t, ValueByteReference> buffer,
                 InstructionCache cc,
                 llvm::DenseMap<llvm::Instruction*, llvm::APInt> assumptions,
                 uint64_t ct)
        : vec(vec), vecflag(vecflag), buffer(buffer), cache(cc),
          assumptions(assumptions), ct(ct){};
    backup_point() = default;
    backup_point(const backup_point&) = default;
    backup_point(const backup_point&&) noexcept = default;
    backup_point& operator=(const backup_point&) = default;
    backup_point& operator=(backup_point&&) noexcept = default;
  };

  llvm::DenseMap<BasicBlock*, backup_point> BBbackup;
  void branch_backup_impl(BasicBlock* bb) {
    //

    printvalue2("backing up");
    printvalue2(this->counter);
    printvalueforce2("dbg1");
    BBbackup[bb] = backup_point(vec, vecflag, this->buffer, this->cache,
                                this->assumptions, this->counter);
    printvalueforce2("dbg2");
  }

  void load_backup_impl(BasicBlock* bb) {
    if (BBbackup.contains(bb)) {

      printvalue2("loading backup");
      backup_point bbinfo = BBbackup[bb];
      vec = bbinfo.vec;
      vecflag = bbinfo.vecflag;
      this->buffer = bbinfo.buffer;
      this->cache = bbinfo.cache;
      this->assumptions = bbinfo.assumptions;
      this->counter = bbinfo.ct;
    }
  }

  void createFunction_impl() {
    std::vector<llvm::Type*> argTypes;
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::Type::getInt64Ty(this->context));
    argTypes.push_back(llvm::PointerType::get(this->context, 0));
    argTypes.push_back(
        llvm::PointerType::get(this->context, 0)); // temp fix TEB

    auto functionType = llvm::FunctionType::get(
        llvm::Type::getInt64Ty(this->context), argTypes, 0);

    const std::string function_name = "main";
    this->fnc =
        llvm::Function::Create(functionType, llvm::Function::ExternalLinkage,
                               function_name.c_str(), this->M);
  }

  void InitRegisters_impl() {
    // rsp
    // rsp_unaligned = %rsp % 16
    // rsp_aligned_to16 = rsp - rsp_unaligned
    auto reg = Register::RAX;
    auto argEnd = this->fnc->arg_end();
    for (auto argIt = this->fnc->arg_begin(); argIt != argEnd; ++argIt) {

      Argument* arg = &*argIt;
      arg->setName(magic_enum::enum_name(reg));

      if (std::next(argIt) == argEnd) {
        arg->setName("memory");
        this->memoryAlloc = arg;
      } else {
        // arg->setName(ZydisRegisterGetString(zydisRegister));
        printvalue2(magic_enum::enum_name(reg));
        printvalue(arg);
        this->SetRegisterValue(reg, arg);
        reg = static_cast<Register>(static_cast<int>(reg) + 1);
      }
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