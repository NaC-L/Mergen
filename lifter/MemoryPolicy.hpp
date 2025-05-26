#pragma once

#include <assert.h>
#include <concepts>
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

template <typename T>
concept MemoryPolicyConcept = requires(T t) {
  {
    t.setDefaultMode_impl(std::declval<MemoryAccessMode>())
  } -> std::same_as<void>;
  {
    t.addRange_impl(std::declval<uint64_t>(), std::declval<uint64_t>(),
                    std::declval<MemoryAccessMode>())
  } -> std::same_as<void>;
  {
    t.getAccessMode_impl(std::declval<uint64_t>())
  } -> std::same_as<MemoryAccessMode>;
  {
    t.isRangeFullyCovered_impl(std::declval<uint64_t>(),
                               std::declval<uint64_t>(),
                               std::declval<MemoryAccessMode>())
  } -> std::same_as<bool>;
};

template <typename Derived> class MemoryPolicyBase {
public:
  MemoryPolicyBase() {
    static_assert(MemoryPolicyConcept<Derived>,
                  "Derived should satisfy MemoryPolicyConcept");
  }
  void setDefaultMode(MemoryAccessMode mode) {
    static_cast<Derived*>(this)->setDefaultMode_impl(mode);
  }

  // inclusive range
  void addRange(uint64_t start, uint64_t end, MemoryAccessMode mode) {
    static_cast<Derived*>(this)->addRange_impl(start, end, mode);
  }

  MemoryAccessMode getAccessMode(uint64_t address) const {
    return static_cast<const Derived*>(this)->getAccessMode_impl(address);
  }

  // inclusive range
  bool isRangeFullyCovered(uint64_t start, uint64_t end,
                           MemoryAccessMode mode) const {
    return static_cast<const Derived*>(this)->isRangeFullyCovered_impl(
        start, end, mode);
  }

  bool isSymbolic(uint64_t address) {
    return getAccessMode(address) == MemoryAccessMode::SYMBOLIC;
  }

  bool isConcrete(uint64_t address) {
    return getAccessMode(address) == MemoryAccessMode::CONCRETE;
  }
};

// Dynamic mode, for when we need concolic execution
class MemoryPolicyDynamic : public MemoryPolicyBase<MemoryPolicyDynamic> {
public:
  std::set<MemoryRange> range;
  MemoryAccessMode defaultMode;

  MemoryPolicyDynamic() { defaultMode = MemoryAccessMode::SYMBOLIC; }

  MemoryPolicyDynamic(MemoryPolicyDynamic& other) {
    range = other.range;
    defaultMode = other.defaultMode;
  };

  MemoryPolicyDynamic(MemoryPolicyDynamic&& other) {
    range = std::move(other.range);
    defaultMode = std::move(other.defaultMode);
  };

  void setDefaultMode_impl(MemoryAccessMode mode) { defaultMode = mode; }

  // inclusive range
  void addRange_impl(uint64_t start, uint64_t end, MemoryAccessMode mode) {
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

  MemoryAccessMode getAccessMode_impl(uint64_t address) const {
    auto it = range.upper_bound({address, address, defaultMode});
    if (it != range.begin()) {
      --it;
      if (address >= it->start && address <= it->end)
        return it->mode;
    }
    return defaultMode;
  }

  // inclusive range
  bool isRangeFullyCovered_impl(uint64_t start, uint64_t end,
                                MemoryAccessMode mode) const {
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
};

// Fully symbolic, for when we go fully symbolic with everything
class MemoryPolicyFullySymbolic
    : public MemoryPolicyBase<MemoryPolicyFullySymbolic> {
public:
  MemoryPolicyFullySymbolic() {}

  MemoryPolicyFullySymbolic(MemoryPolicyFullySymbolic& other){

  };

  MemoryPolicyFullySymbolic(MemoryPolicyFullySymbolic&& other){

  };

  void setDefaultMode_impl(MemoryAccessMode mode) { return; }

  // inclusive range
  void addRange_impl(uint64_t start, uint64_t end, MemoryAccessMode mode) {
    return;
  }

  MemoryAccessMode getAccessMode_impl(uint64_t address) const {
    return MemoryAccessMode::SYMBOLIC;
  }

  // inclusive range
  bool isRangeFullyCovered_impl(uint64_t start, uint64_t end,
                                MemoryAccessMode mode) const {
    return MemoryAccessMode::SYMBOLIC == mode;
  }
};

// Fully concrete, could use it with emu
class MemoryPolicyFullyConcrete
    : public MemoryPolicyBase<MemoryPolicyFullyConcrete> {
public:
  MemoryPolicyFullyConcrete() {}

  MemoryPolicyFullyConcrete(MemoryPolicyFullyConcrete& other){

  };

  MemoryPolicyFullyConcrete(MemoryPolicyFullyConcrete&& other){

  };

  void setDefaultMode_impl(MemoryAccessMode mode) { return; }

  // inclusive range
  void addRange_impl(uint64_t start, uint64_t end, MemoryAccessMode mode) {
    return;
  }

  MemoryAccessMode getAccessMode_impl(uint64_t address) const {
    return MemoryAccessMode::CONCRETE;
  }

  // inclusive range
  bool isRangeFullyCovered_impl(uint64_t start, uint64_t end,
                                MemoryAccessMode mode) const {
    return MemoryAccessMode::CONCRETE == mode;
  }
};

using MemoryPolicy = MemoryPolicyDynamic;