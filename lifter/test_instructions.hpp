
#include "lifterClass.h"
#include <Zydis/Decoder.h>
#include <Zydis/DecoderTypes.h>
#include <Zydis/Disassembler.h>
#include <Zydis/Register.h>

class Tester {
public:
  ZydisDecoder decoder;
  lifterClass* lifter;

  Tester(lifterClass* lifter, bool is64Bit = true) : lifter(lifter) {

    ZydisDecoderInit(&decoder,
                     is64Bit ? ZYDIS_MACHINE_MODE_LONG_64
                             : ZYDIS_MACHINE_MODE_LEGACY_32,
                     is64Bit ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
  }

  Value* getRegister(ZydisRegister reg) {
    auto val = lifter->GetRegisterValue(reg);
    printvalueforce(val);
    return val;
  }

  void setRegister(ZydisRegister reg, uint64_t value) {
    lifter->SetRegisterValue(reg, lifter->builder.getInt64(value));
  }

  Value* getMemory(ZydisRegister reg) {

    auto val = lifter->GetRegisterValue(reg);
    return val;
  }

  void setMemory(ZydisRegister reg, uint64_t value) {
    lifter->SetRegisterValue(reg, lifter->builder.getInt64(value));
  }

  void disassembleBytesAndLift(const std::vector<uint8_t>& bytes) {

    ZydisDecoderDecodeFull(&decoder, bytes.data(), 15, &(lifter->instruction),
                           lifter->operands);

    lifter->liftInstructionSemantics();
  }
};
