#include "utils.h"
#include "llvm/IR/Value.h"
#include <chrono>
#include <iostream>
#include <llvm/Analysis/ValueLattice.h>
#include <llvm/Support/KnownBits.h>
#include <map>

/*


float intBitsToFloat(int bits) {
    // Extract components from the int using IEEE 754 single precision format
    int sign = (bits >> 31) & 0x1;
    int exponent = (bits >> 23) & 0xFF;
    int mantissa = bits & 0x7FFFFF;

    // Build float value according to IEEE 754 formula
    float value = 0;
    if (exponent == 0) {
        if (mantissa == 0) {
            value = sign ? -0.0f : 0.0f;
        } else {
            // Denormalized number
            value = (sign ? -1.0f : 1.0f) * (mantissa / (float)(1 << 23)) *
powf(2.0f, -126);
        }
    } else if (exponent == 0xFF) {
        if (mantissa == 0) {
            value = sign ? -INFINITY : INFINITY;
        } else {
            value = NAN;
        }
    } else {
        // Normalized number
        value = (sign ? -1.0f : 1.0f) * (1.0f + mantissa / (float)(1 << 23)) *
powf(2.0f, exponent - 127);
    }

    return value;
}
int floatBitsToInt(float f) {
    if (f == 0.0f) {
        return (std::signbit(f) ? 0x80000000 : 0);
    }

    if (std::isinf(f)) {
        return (f < 0 ? 0xFF800000 : 0x7F800000);
    }

    if (std::isnan(f)) {
        return 0x7FC00000;  // One common NaN pattern
    }

    int sign = std::signbit(f) ? 1 : 0;
    float abs_f = std::fabs(f);

    int exponent = std::ilogbf(abs_f) + 127;  // Get biased exponent

    // Handle denormals
    if (exponent <= 0) {
        float mantissa_f = abs_f * powf(2.0f, 149);  // 126 + 23
        int mantissa = (int)mantissa_f;
        return (sign << 31) | mantissa;
    }

    // Extract mantissa (23 bits of precision)
    float mantissa_f = (abs_f / powf(2.0f, std::ilogbf(abs_f)) - 1.0f) *
(float)(1 << 23); int mantissa = (int)mantissa_f;

    return (sign << 31) | (exponent << 23) | mantissa;
}

*/

namespace debugging {
  int ic = 1;
  int increaseInstCounter() { return ++ic; }
  bool shouldDebug = false;
  llvm::raw_ostream* debugStream = nullptr;
  std::unique_ptr<llvm::raw_fd_ostream> fileStream;

  void enableDebug(const std::string& filename = "") {
    shouldDebug = true;
    if (!filename.empty()) {
      std::error_code EC;
      fileStream = std::make_unique<llvm::raw_fd_ostream>(filename, EC);
      if (EC) {
        llvm::errs() << "Error opening debug file: " << EC.message() << "\n";
        fileStream.reset();
        debugStream = &llvm::errs();
        shouldDebug = false;
        return;
      }
      debugStream = fileStream.get();
    } else {
      debugStream = &llvm::outs();
    }
    llvm::outs() << "Debugging enabled\n";
  }

  void printLLVMValue(llvm::Value* v, const char* name) {
    if (!shouldDebug || !debugStream)
      return;
    *debugStream << " " << name << " : ";
    v->print(*debugStream);
    *debugStream << "\n";
    debugStream->flush();
  }

  // Other functions remain the same, but use debugStream instead of
  // llvm::outs() For example:
  template <typename T> void printValue(const T& v, const char* name) {
    if (!shouldDebug || !debugStream)
      return;
    if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, int8_t>) {
      *debugStream << " " << name << " : " << static_cast<int>(v) << "\n";
      debugStream->flush();
      return;
    } else
      *debugStream << " " << name << " : " << v << "\n";
    debugStream->flush();
  }

  void doIfDebug(const std::function<void(void)>& dothis) {
    if (!shouldDebug)
      return;
    (dothis)();
  }
  template void printValue<uint64_t>(const uint64_t& v, const char* name);
  template void printValue<uint32_t>(const uint32_t& v, const char* name);
  template void printValue<uint16_t>(const uint16_t& v, const char* name);
  template void printValue<uint8_t>(const uint8_t& v, const char* name);
  template void printValue<int64_t>(const int64_t& v, const char* name);
  template void printValue<int32_t>(const int32_t& v, const char* name);
  template void printValue<int16_t>(const int16_t& v, const char* name);
  template void printValue<int8_t>(const int8_t& v, const char* name);
  template void printValue<bool>(const bool& v, const char* name);
  template void printValue<std::string>(const std::string& v, const char* name);
  template void printValue<char*>(char* const& v, const char* name);
  template void printValue<char[256]>(char const (&)[256], const char* name);
  template void
  printValue<llvm::FormattedNumber>(llvm::FormattedNumber const(&),
                                    const char* name);
  template void
  printValue<llvm::ValueLatticeElement>(const llvm::ValueLatticeElement& v,
                                        const char* name);
  template void printValue<llvm::KnownBits>(const llvm::KnownBits& v,
                                            const char* name);
  template void printValue<llvm::APInt>(const llvm::APInt& v, const char* name);
  template void printValue<llvm::ConstantRange>(const llvm::ConstantRange& v,
                                                const char* name);
} // namespace debugging

namespace argparser {
  void printHelp() {
    std::cerr << "Options:\n"
              << "  -d, --enable-debug   Enable debugging mode\n"
              << "  -h                   Display this help message\n";
  }

  std::map<std::string, std::function<void()>> options = {
      {"-d", []() { debugging::enableDebug("debug.txt"); }},
      //
      {"-h", printHelp}};

  void parseArguments(std::vector<std::string>& args) {
    std::vector<std::string> newArgs;

    for (const auto& arg : args) {
      // cout << arg << "\n";
      if (options.find(arg) != options.end())
        options[arg]();
      else if (*(arg.c_str()) == '-')
        printHelp();
      else
        newArgs.push_back(arg);
    }

    args.swap(newArgs);
  }

} // namespace argparser

namespace timer {
  using clock = std::chrono::high_resolution_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double, std::milli>;

  time_point startTime;
  bool running = false;

  void startTimer() {
    startTime = clock::now();
    running = true;
  }

  double getTimer() {
    if (running) {
      return std::chrono::duration_cast<duration>(clock::now() - startTime)
          .count();
    }
    return 0.0;
  }

  double stopTimer() {
    if (running) {
      running = false;
      return std::chrono::duration_cast<duration>(clock::now() - startTime)
          .count();
    }
    return 0.0;
  }

  void resetTimer() {
    startTime = clock::now();
    running = true;
  }
} // namespace timer