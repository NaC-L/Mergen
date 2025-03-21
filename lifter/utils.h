#pragma once
#include "llvm/IR/Value.h"
#include <linuxpe>
#include <llvm/Support/raw_ostream.h>

// #define _NODEV why?

#ifndef UNREACHABLE
#define UNREACHABLE(msg)                                                       \
  do {                                                                         \
                                                                               \
    llvm::outs().flush();                                                      \
    std::cout.flush();                                                         \
    llvm::llvm_unreachable_internal(msg, __FILE__, __LINE__);                  \
  } while (0)
#endif

#ifndef _NODEV
#define printvalue(x)                                                          \
  do {                                                                         \
    debugging::printLLVMValue(x, #x);                                          \
  } while (0);
// outs() << " " #x " : "; x->print(outs());
// outs() << "\n";  outs().flush();
#define printvalue2(x)                                                         \
  do {                                                                         \
    debugging::printValue(x, #x);                                              \
  } while (0);
#else
#define printvalue(x) ((void)0);
#define printvalue2(x) ((void)0);
#endif // _NODEV

#define printvalueforce(x)                                                     \
  do {                                                                         \
    outs() << " " #x " : ";                                                    \
    x->print(outs());                                                          \
    outs() << "\n";                                                            \
    outs().flush();                                                            \
  } while (0);

#define printvalueforce2(x)                                                    \
  do {                                                                         \
    llvm::outs() << " " #x " : " << x << "\n";                                 \
    llvm::outs().flush();                                                      \
  } while (0);

namespace debugging {
  int increaseInstCounter();
  void enableDebug(const std::string& filename);
  void printLLVMValue(llvm::Value* v, const char* name);
  void doIfDebug(const std::function<void(void)>& dothis);

  extern bool shouldDebug;
  extern llvm::raw_ostream* debugStream;

  template <typename T> void printValue(const T& v, const char* name) {
    if (!shouldDebug || !debugStream)
      return;
    if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, int8_t>) {
      *debugStream << " " << name << " : " << static_cast<int>(v) << "\n";
      debugStream->flush();
      return;
    } /*
    if constexpr (std::is_same_v<T, z3::expr>) {
      *debugStream << " " << name << " : "
                   << static_cast<z3::expr>(v).to_string() << "\n";
      debugStream->flush();
      return;
    }*/
    else
      *debugStream << " " << name << " : " << v << "\n";
    debugStream->flush();
  }

} // namespace debugging

namespace argparser {
  void parseArguments(std::vector<std::string>& args);
} // namespace argparser

namespace timer {
  void startTimer();
  double stopTimer();
  double getTimer();
  void suspendTimer();
  void resumeTimer();
} // namespace timer
