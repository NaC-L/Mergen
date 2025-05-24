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

class MemoryPolicy {
private:
  MemoryAccessMode defaultMode;

  std::set<MemoryRange> range;

public:
  MemoryPolicy() { defaultMode = MemoryAccessMode::SYMBOLIC; }
  MemoryPolicy(MemoryPolicy& other)
      : range(other.range), defaultMode(other.defaultMode){};
  MemoryPolicy(MemoryPolicy&& other)
      : range(other.range), defaultMode(other.defaultMode){};

  void setDefaultMode(MemoryAccessMode mode) { defaultMode = mode; }

  // inclusive range
  void addRange(uint64_t start, uint64_t end, MemoryAccessMode mode) {
    // make sure start is smoller than end
    if (start > end)
      std::swap(start, end);

    // 1- remove overlapping ranges
    auto it = range.lower_bound({start, start, mode});
    if (it != range.begin())
      --it;

    std::vector<MemoryRange> toAdd;
    while (it != range.end() && it->start <= end) {
      if (it->end < start) {
        ++it;
        continue;
      }

      // track splitted ranges, (( should we also merge the ranges? ))
      if (it->start < start)
        toAdd.push_back({it->start, start - 1, it->mode});
      if (it->end > end)
        toAdd.push_back({end + 1, it->end, it->mode});

      it = range.erase(it);
    }

    // 2 - Add new range
    toAdd.push_back({start, end, mode});
    for (auto& r : toAdd) {
      range.insert(r);
    }
  }

  MemoryAccessMode getAccessMode(uint64_t address) const {
    auto it = range.upper_bound({address, address, defaultMode});
    if (it != range.begin()) {
      --it;
      if (address >= it->start && address <= it->end)
        return it->mode;
    }
    return defaultMode;
  }

  // inclusive range
  bool isRangeFullyCovered(uint64_t start, uint64_t end,
                           MemoryAccessMode mode) const {
    if (start > end)
      std::swap(start, end);

    uint64_t cursor = start;

    // 1- find the first range that might contain "start"
    auto it = range.upper_bound({start, start, mode});
    if (it != range.begin())
      --it;

    while (cursor <= end) {
      // 2 - if we're out of ranges, rely on default mode
      if (it == range.end() || it->start > cursor) {
        uint64_t gapStart = cursor;
        uint64_t gapEnd =
            (it != range.end()) ? std::min(end, it->start - 1) : end;

        if (defaultMode != mode)
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