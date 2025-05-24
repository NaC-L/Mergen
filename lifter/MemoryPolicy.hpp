#pragma once

#include <llvm/IR/Value.h>
#include <set>
#include <vector>

namespace llvm {
  class Module;
  class Function;
} // namespace llvm

enum class MemoryAccessMode : uint8_t { SYMBOLIC, CONCRETE };

struct MemoryRange {
  uint64_t start, end;
  MemoryAccessMode mode;
  bool operator<(MemoryRange const& o) const { return start < o.start; }
};

enum class StaticMode : uint8_t { Dynamic, FullyConcrete, FullySymbolic };

template <StaticMode Mode> struct DefaultModeMember {};

template <> struct DefaultModeMember<StaticMode::Dynamic> {
  std::set<MemoryRange> range;
  MemoryAccessMode defaultMode;
};

template <StaticMode staticMode = StaticMode::Dynamic>
class MemoryPolicy : DefaultModeMember<staticMode> {
public:
  MemoryPolicy() {
    if constexpr (staticMode == StaticMode::Dynamic) {
      this->defaultMode = MemoryAccessMode::SYMBOLIC;
    }
  }

  MemoryPolicy(MemoryPolicy& other) {
    if constexpr (staticMode == StaticMode::Dynamic) {
      this->range = other.range;
      this->defaultMode = other.defaultMode;
    }
  };

  MemoryPolicy(MemoryPolicy&& other) {
    if constexpr (staticMode == StaticMode::Dynamic) {
      this->range = std::move(other.range);
      this->defaultMode = std::move(other.defaultMode);
    }
  };

  void setDefaultMode(MemoryAccessMode mode) {
    if constexpr (staticMode == StaticMode::Dynamic) {
      this->defaultMode = mode;
    }
  }

  // inclusive range
  void addRange(uint64_t start, uint64_t end, MemoryAccessMode mode) {
    if constexpr (staticMode != StaticMode::Dynamic) {
      return;
    }
    // make sure start is smoller than end
    if (start > end)
      std::swap(start, end);

    // 1- remove overlapping ranges
    auto it = this->range.lower_bound({start, start, mode});
    if (it != this->range.begin())
      --it;

    std::vector<MemoryRange> toAdd;
    while (it != this->range.end() && it->start <= end) {
      if (it->end < start) {
        ++it;
        continue;
      }

      // track splitted ranges, (( should we also merge the ranges? ))
      if (it->start < start)
        toAdd.push_back({it->start, start - 1, it->mode});
      if (it->end > end)
        toAdd.push_back({end + 1, it->end, it->mode});

      it = this->range.erase(it);
    }

    // 2 - Add new range
    toAdd.push_back({start, end, mode});
    for (auto& r : toAdd) {
      this->range.insert(r);
    }
  }

  MemoryAccessMode getAccessMode(uint64_t address) const {

    switch (staticMode) {
    case StaticMode::FullyConcrete:
      return MemoryAccessMode::CONCRETE;
    case StaticMode::FullySymbolic:
      return MemoryAccessMode::SYMBOLIC;
    default:
      break;
    }

    auto it = this->range.upper_bound({address, address, this->defaultMode});
    if (it != this->range.begin()) {
      --it;
      if (address >= it->start && address <= it->end)
        return it->mode;
    }
    return this->defaultMode;
  }

  // inclusive range
  bool isRangeFullyCovered(uint64_t start, uint64_t end,
                           MemoryAccessMode mode) const {

    switch (staticMode) {
    case StaticMode::FullyConcrete:
      return MemoryAccessMode::CONCRETE == mode;
    case StaticMode::FullySymbolic:
      return MemoryAccessMode::SYMBOLIC == mode;
    default:
      break;
    }
    if (start > end)
      std::swap(start, end);

    uint64_t cursor = start;

    // 1- find the first range that might contain "start"
    auto it = this->range.upper_bound({start, start, mode});
    if (it != this->range.begin())
      --it;

    while (cursor <= end) {
      // 2 - if we're out of ranges, rely on default mode
      if (it == this->range.end() || it->start > cursor) {
        uint64_t gapStart = cursor;
        uint64_t gapEnd =
            (it != this->range.end()) ? std::min(end, it->start - 1) : end;

        if (this->defaultMode != mode)
          return false;

        cursor = gapEnd + 1;
        continue;
      }

      // region in range, match node
      if (it->mode != mode)
        return false;

      if (it->start > cursor)
        return false;

      cursor = it->end + 1;
      ++it;
    }

    return true;
  }

  bool isSymbolic(uint64_t address) {
    return getAccessMode(address) == MemoryAccessMode::SYMBOLIC;
  }

  bool isConcrete(uint64_t address) {
    return getAccessMode(address) == MemoryAccessMode::CONCRETE;
  }
};