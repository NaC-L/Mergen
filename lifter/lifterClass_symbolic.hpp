#ifndef LIFTERCLASS_SYMBOLIC_H
#define LIFTERCLASS_SYMBOLIC_H

#include "CommonDisassembler.hpp"
#include "icedDisassembler.hpp"
#include "icedDisassembler_mnemonics.h"
#include "icedDisassembler_registers.h"
#include "lifterClass.hpp"
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Metadata.h>
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

class lifterSymbolic : public lifterClassBase<
                           lifterSymbolic<Register, Mnemonic, DisassemblerBase>,
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
  llvm::Value* ctx;
  StructType* type;

  llvm::Value* GetRegisterValue_impl(Register key) {
    int index = getRegisterIndex(key);
    // auto size = getRegisterSize(key);

    llvm::Value* fieldPtr =
        this->builder->CreateStructGEP(type, ctx, index, "reg_ptr");

    llvm::Value* val = this->builder->CreateLoad(
        llvm::Type::getInt64Ty(this->context), fieldPtr, "reg_val");

    return val;
  }

  void SetRegisterValue_impl(Register key, llvm::Value* val) {
    int index = getRegisterIndex(key);

    llvm::Value* fieldPtr =
        this->builder->CreateStructGEP(type, ctx, (uint64_t)index, "reg_ptr");

    this->builder->CreateStore(val, fieldPtr);
  }

  llvm::Value* GetFlagValue_impl(Flag key) {
    int index = key + 16;
    // auto size = getRegisterSize(key);

    llvm::Value* fieldPtr =
        this->builder->CreateStructGEP(type, ctx, index, "reg_ptr");

    llvm::Value* val = this->builder->CreateLoad(this->builder->getInt1Ty(),
                                                 fieldPtr, "reg_val");

    return val;
  }

  void SetFlagValue_impl(Flag key, llvm::Value* val) {
    int index = key + 16;

    llvm::Value* fieldPtr =
        this->builder->CreateStructGEP(type, ctx, (uint64_t)index, "reg_ptr");

    this->builder->CreateStore(
        this->builder->CreateTrunc(val, this->builder->getInt1Ty()), fieldPtr);
  }

  constexpr ControlFlow getControlFlow_impl() { return ControlFlow::Basic; }

  void branch_backup_impl(BasicBlock* bb) {
    //
    return;
  }

  void load_backup_impl(BasicBlock* bb) {
    //
    return;
  }
  void createFunction_impl() {
    std::vector<llvm::Type*> argTypes;

    std::vector<llvm::Type*> structTypes;
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));
    structTypes.push_back(llvm::Type::getInt64Ty(this->context));

    // 12 flags
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));
    structTypes.push_back(llvm::Type::getInt1Ty(this->context));

    type = StructType::create(structTypes, "CTX");

    // returnvalue = builder->CreateInsertValue(myStruct, rax, {0});
    // builder->CreateExtractValue(Value * Agg, ArrayRef<unsigned int> Idxs)
    // llvm::PointerType* ctxPtrType = llvm::PointerType::getUnqual(type);
    // argTypes.push_back(ctxPtrType);
    argTypes.push_back(type); // temp fix TEB
    argTypes.push_back(
        llvm::PointerType::get(this->context, 0)); // temp fix TEB

    auto functionType = llvm::FunctionType::get(
        llvm::Type::getInt64Ty(this->context), argTypes, 0);

    const std::string function_name = "main";
    this->fnc =
        llvm::Function::Create(functionType, llvm::Function::ExternalLinkage,
                               function_name.c_str(), this->M);

    ctx = this->fnc->getArg(0);
    this->memoryAlloc = this->fnc->getArg(1);

    this->fnc->addParamAttr(1, Attribute::NoAlias);
  }

  void InitRegisters_impl() {
    // rsp
    // rsp_unaligned = %rsp % 16
    // rsp_aligned_to16 = rsp - rsp_unaligned
    // auto reg = Register::RAX;
    // auto argEnd = this->fnc->arg_end();
    // for (auto argIt = this->fnc->arg_begin(); argIt != argEnd; ++argIt) {

    //   Argument* arg = &*argIt;
    //   arg->setName(magic_enum::enum_name(reg));

    //   if (std::next(argIt) == argEnd) {
    //     arg->setName("memory");
    //     this->memoryAlloc = arg;
    //   } else {
    //     // arg->setName(ZydisRegisterGetString(zydisRegister));
    //     printvalue2(magic_enum::enum_name(reg));
    //     printvalue(arg);
    //     // int index = getRegisterIndex(reg);
    //     // vec[index] = arg;
    //     reg = static_cast<Register>(static_cast<int>(reg) + 1);
    //   }
    // }
    // printvalue(GetRegisterValue(Register::RAX));

    ctx = this->builder->CreateAlloca(type);

    this->builder->CreateStore(this->fnc->getArg(0), ctx);
    return;
  }
};

#endif