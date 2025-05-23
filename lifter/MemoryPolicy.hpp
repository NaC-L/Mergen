#pragma once

#include "utils.h"
#include <llvm/IR/Value.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace llvm {
  class Module;
  class Function;
} // namespace llvm

enum class MemoryAccessMode : uint8_t { SYMBOLIC, CONCRETE };

struct MemoryRange {
  uint64_t start;
  uint64_t end;
  bool operator<(MemoryRange const& o) const { return start < o.start; }
};

class MemoryPolicy {
private:
  MemoryAccessMode defaultMode;

  std::set<MemoryRange> symbolicRange;
  std::set<MemoryRange> concreteRange;

public:
  MemoryPolicy() { defaultMode = MemoryAccessMode::SYMBOLIC; }
  MemoryPolicy(MemoryPolicy& other)
      : symbolicRange(other.symbolicRange), concreteRange(other.concreteRange),
        defaultMode(other.defaultMode){};
  MemoryPolicy(MemoryPolicy&& other)
      : symbolicRange(other.symbolicRange), concreteRange(other.concreteRange),
        defaultMode(other.defaultMode){};

  void setDefaultMode(MemoryAccessMode mode) { defaultMode = mode; }

  void addRangeOverrideSymbolic(uint64_t start, uint64_t end) {
    printvalue2("Adding " + std::to_string(start) + "-" + std::to_string(end));
    symbolicRange.insert({.start = start, .end = end});
  }

  void addRangeOverrideConcrete(uint64_t start, uint64_t end) {
    printvalue2("Adding " + std::to_string(start) + "-" + std::to_string(end));
    concreteRange.insert({.start = start, .end = end});
  }

  MemoryAccessMode getAccessMode(uint64_t address) {
    if (isSymbolic(address)) {
      return MemoryAccessMode::SYMBOLIC;
    }
    return MemoryAccessMode::CONCRETE;
  }

  bool isSymbolic(uint64_t address) {
    auto it = symbolicRange.upper_bound({address, address});
    if (it == symbolicRange.begin())
      return defaultMode == MemoryAccessMode::SYMBOLIC;
    printvalue2("symbolic");
    --it;
    printvalue2(it->end);
    printvalue2(address <= it->end);
    printvalue2(address <= it->end ? true
                                   : defaultMode == MemoryAccessMode::SYMBOLIC);
    return address <= it->end ? true
                              : defaultMode == MemoryAccessMode::SYMBOLIC;
  }

  bool isConcrete(uint64_t address) {
    auto it = concreteRange.upper_bound({address, address});
    if (it == concreteRange.begin())
      return defaultMode == MemoryAccessMode::CONCRETE;

    --it;
    return address <= it->end ? true
                              : defaultMode == MemoryAccessMode::CONCRETE;
  }
};