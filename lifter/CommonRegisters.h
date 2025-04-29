#ifndef COMMON_REGISTERS_H
#define COMMON_REGISTERS_H

#include <cstdint>
enum class RegisterInternal : uint8_t {
  None = 0,
  AL,
  CL,
  DL,
  BL,
  AH,
  CH,
  DH,
  BH,
  SPL,
  BPL,
  SIL,
  DIL,
  R8B,
  R9B,
  R10B,
  R11B,
  R12B,
  R13B,
  R14B,
  R15B,
  AX,
  CX,
  DX,
  BX,
  SP,
  BP,
  SI,
  DI,
  R8W,
  R9W,
  R10W,
  R11W,
  R12W,
  R13W,
  R14W,
  R15W,
  EAX,
  ECX,
  EDX,
  EBX,
  ESP,
  EBP,
  ESI,
  EDI,
  R8D,
  R9D,
  R10D,
  R11D,
  R12D,
  R13D,
  R14D,
  R15D,
  RAX,
  RCX,
  RDX,
  RBX,
  RSP,
  RBP,
  RSI,
  RDI,
  R8,
  R9,
  R10,
  R11,
  R12,
  R13,
  R14,
  R15,
  EIP,
  RIP,
  ES,
  CS,
  SS,
  DS,
  FS,
  GS,
  XMM0,
  XMM1,
  XMM2,
  XMM3,
  XMM4,
  XMM5,
  XMM6,
  XMM7,
  XMM8,
  XMM9,
  XMM10,
  XMM11,
  XMM12,
  XMM13,
  XMM14,
  XMM15,
  XMM16,
  XMM17,
  XMM18,
  XMM19,
  XMM20,
  XMM21,
  XMM22,
  XMM23,
  XMM24,
  XMM25,
  XMM26,
  XMM27,
  XMM28,
  XMM29,
  XMM30,
  XMM31,
  YMM0,
  YMM1,
  YMM2,
  YMM3,
  YMM4,
  YMM5,
  YMM6,
  YMM7,
  YMM8,
  YMM9,
  YMM10,
  YMM11,
  YMM12,
  YMM13,
  YMM14,
  YMM15,
  YMM16,
  YMM17,
  YMM18,
  YMM19,
  YMM20,
  YMM21,
  YMM22,
  YMM23,
  YMM24,
  YMM25,
  YMM26,
  YMM27,
  YMM28,
  YMM29,
  YMM30,
  YMM31,
  ZMM0,
  ZMM1,
  ZMM2,
  ZMM3,
  ZMM4,
  ZMM5,
  ZMM6,
  ZMM7,
  ZMM8,
  ZMM9,
  ZMM10,
  ZMM11,
  ZMM12,
  ZMM13,
  ZMM14,
  ZMM15,
  ZMM16,
  ZMM17,
  ZMM18,
  ZMM19,
  ZMM20,
  ZMM21,
  ZMM22,
  ZMM23,
  ZMM24,
  ZMM25,
  ZMM26,
  ZMM27,
  ZMM28,
  ZMM29,
  ZMM30,
  ZMM31,
  K0,
  K1,
  K2,
  K3,
  K4,
  K5,
  K6,
  K7,
  BND0,
  BND1,
  BND2,
  BND3,
  CR0,
  CR1,
  CR2,
  CR3,
  CR4,
  CR5,
  CR6,
  CR7,
  CR8,
  CR9,
  CR10,
  CR11,
  CR12,
  CR13,
  CR14,
  CR15,
  DR0,
  DR1,
  DR2,
  DR3,
  DR4,
  DR5,
  DR6,
  DR7,
  DR8,
  DR9,
  DR10,
  DR11,
  DR12,
  DR13,
  DR14,
  DR15,
  ST0,
  ST1,
  ST2,
  ST3,
  ST4,
  ST5,
  ST6,
  ST7,
  MM0,
  MM1,
  MM2,
  MM3,
  MM4,
  MM5,
  MM6,
  MM7,
  TR0,
  TR1,
  TR2,
  TR3,
  TR4,
  TR5,
  TR6,
  TR7,
  TMM0,
  TMM1,
  TMM2,
  TMM3,
  TMM4,
  TMM5,
  TMM6,
  TMM7,

  EFLAGS,
  RFLAGS,

  START = None,
  END = TMM7
};

template <typename T>
concept Registers = requires() {
  { T::None };
  { T::AL };
  { T::CL };
  { T::DL };
  { T::BL };
  { T::AH };
  { T::CH };
  { T::DH };
  { T::BH };
  { T::SPL };
  { T::BPL };
  { T::SIL };
  { T::DIL };
  { T::R8B };
  { T::R9B };
  { T::R10B };
  { T::R11B };
  { T::R12B };
  { T::R13B };
  { T::R14B };
  { T::R15B };
  { T::AX };
  { T::CX };
  { T::DX };
  { T::BX };
  { T::SP };
  { T::BP };
  { T::SI };
  { T::DI };
  { T::R8W };
  { T::R9W };
  { T::R10W };
  { T::R11W };
  { T::R12W };
  { T::R13W };
  { T::R14W };
  { T::R15W };
  { T::EAX };
  { T::ECX };
  { T::EDX };
  { T::EBX };
  { T::ESP };
  { T::EBP };
  { T::ESI };
  { T::EDI };
  { T::R8D };
  { T::R9D };
  { T::R10D };
  { T::R11D };
  { T::R12D };
  { T::R13D };
  { T::R14D };
  { T::R15D };
  { T::RAX };
  { T::RCX };
  { T::RDX };
  { T::RBX };
  { T::RSP };
  { T::RBP };
  { T::RSI };
  { T::RDI };
  { T::R8 };
  { T::R9 };
  { T::R10 };
  { T::R11 };
  { T::R12 };
  { T::R13 };
  { T::R14 };
  { T::R15 };
  { T::EIP };
  { T::RIP };
  { T::ES };
  { T::CS };
  { T::SS };
  { T::DS };
  { T::FS };
  { T::GS };
  { T::XMM0 };
  { T::XMM1 };
  { T::XMM2 };
  { T::XMM3 };
  { T::XMM4 };
  { T::XMM5 };
  { T::XMM6 };
  { T::XMM7 };
  { T::XMM8 };
  { T::XMM9 };
  { T::XMM10 };
  { T::XMM11 };
  { T::XMM12 };
  { T::XMM13 };
  { T::XMM14 };
  { T::XMM15 };
  { T::XMM16 };
  { T::XMM17 };
  { T::XMM18 };
  { T::XMM19 };
  { T::XMM20 };
  { T::XMM21 };
  { T::XMM22 };
  { T::XMM23 };
  { T::XMM24 };
  { T::XMM25 };
  { T::XMM26 };
  { T::XMM27 };
  { T::XMM28 };
  { T::XMM29 };
  { T::XMM30 };
  { T::XMM31 };
  { T::YMM0 };
  { T::YMM1 };
  { T::YMM2 };
  { T::YMM3 };
  { T::YMM4 };
  { T::YMM5 };
  { T::YMM6 };
  { T::YMM7 };
  { T::YMM8 };
  { T::YMM9 };
  { T::YMM10 };
  { T::YMM11 };
  { T::YMM12 };
  { T::YMM13 };
  { T::YMM14 };
  { T::YMM15 };
  { T::YMM16 };
  { T::YMM17 };
  { T::YMM18 };
  { T::YMM19 };
  { T::YMM20 };
  { T::YMM21 };
  { T::YMM22 };
  { T::YMM23 };
  { T::YMM24 };
  { T::YMM25 };
  { T::YMM26 };
  { T::YMM27 };
  { T::YMM28 };
  { T::YMM29 };
  { T::YMM30 };
  { T::YMM31 };
  { T::ZMM0 };
  { T::ZMM1 };
  { T::ZMM2 };
  { T::ZMM3 };
  { T::ZMM4 };
  { T::ZMM5 };
  { T::ZMM6 };
  { T::ZMM7 };
  { T::ZMM8 };
  { T::ZMM9 };
  { T::ZMM10 };
  { T::ZMM11 };
  { T::ZMM12 };
  { T::ZMM13 };
  { T::ZMM14 };
  { T::ZMM15 };
  { T::ZMM16 };
  { T::ZMM17 };
  { T::ZMM18 };
  { T::ZMM19 };
  { T::ZMM20 };
  { T::ZMM21 };
  { T::ZMM22 };
  { T::ZMM23 };
  { T::ZMM24 };
  { T::ZMM25 };
  { T::ZMM26 };
  { T::ZMM27 };
  { T::ZMM28 };
  { T::ZMM29 };
  { T::ZMM30 };
  { T::ZMM31 };
  { T::K0 };
  { T::K1 };
  { T::K2 };
  { T::K3 };
  { T::K4 };
  { T::K5 };
  { T::K6 };
  { T::K7 };
  { T::BND0 };
  { T::BND1 };
  { T::BND2 };
  { T::BND3 };
  { T::CR0 };
  { T::CR1 };
  { T::CR2 };
  { T::CR3 };
  { T::CR4 };
  { T::CR5 };
  { T::CR6 };
  { T::CR7 };
  { T::CR8 };
  { T::CR9 };
  { T::CR10 };
  { T::CR11 };
  { T::CR12 };
  { T::CR13 };
  { T::CR14 };
  { T::CR15 };
  { T::DR0 };
  { T::DR1 };
  { T::DR2 };
  { T::DR3 };
  { T::DR4 };
  { T::DR5 };
  { T::DR6 };
  { T::DR7 };
  { T::DR8 };
  { T::DR9 };
  { T::DR10 };
  { T::DR11 };
  { T::DR12 };
  { T::DR13 };
  { T::DR14 };
  { T::DR15 };
  { T::ST0 };
  { T::ST1 };
  { T::ST2 };
  { T::ST3 };
  { T::ST4 };
  { T::ST5 };
  { T::ST6 };
  { T::ST7 };
  { T::MM0 };
  { T::MM1 };
  { T::MM2 };
  { T::MM3 };
  { T::MM4 };
  { T::MM5 };
  { T::MM6 };
  { T::MM7 };
  { T::TR0 };
  { T::TR1 };
  { T::TR2 };
  { T::TR3 };
  { T::TR4 };
  { T::TR5 };
  { T::TR6 };
  { T::TR7 };
  { T::TMM0 };
  { T::TMM1 };
  { T::TMM2 };
  { T::TMM3 };
  { T::TMM4 };
  { T::TMM5 };
  { T::TMM6 };
  { T::TMM7 };
  { T::EFLAGS };
  { T::RFLAGS };
  { T::START };
  { T::END };
};

// using RegisterPlaceholder = RegisterInternal;

#endif // COMMON_REGISTERS_H