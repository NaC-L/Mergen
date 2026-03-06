#pragma once

#include <assert.h>
#include <concepts>
#include <llvm/IR/Value.h>
#include <set>

namespace llvm {
  class Module;
  class Function;
} // namespace llvm

enum class FunctionInlineMode : uint8_t { INLINE, OUTLINE };

template <typename T>
concept FunctionInlineConcept = requires(T t) {
  /*
  {
     t.setDefaultMode_impl(std::declval<FunctionInlineMode>())
   } -> std::same_as<void>;
  */
  { t.addAddress_impl(std::declval<uint64_t>()) } -> std::same_as<void>;
  {
    t.getAccessMode_impl(std::declval<uint64_t>())
  } -> std::same_as<FunctionInlineMode>;
};

template <typename Derived> class FunctionInlinePolicyBase {
public:
  FunctionInlinePolicyBase() {
    static_assert(FunctionInlineConcept<Derived>,
                  "Derived should satisfy FunctionInlineConcept");
  }

  // address to outline
  void addAddress(uint64_t address) {
    static_cast<Derived*>(this)->addAddress_impl(address);
  }

  FunctionInlineMode getAccessMode(uint64_t address) const {
    return static_cast<const Derived*>(this)->getAccessMode_impl(address);
  }

  bool isInline(uint64_t address) {
    return getAccessMode(address) == FunctionInlineMode::INLINE;
  }

  bool isOutline(uint64_t address) {
    return getAccessMode(address) == FunctionInlineMode::OUTLINE;
  }
};

// Dynamic mode, for when we need concolic execution
// inline by default
class FunctionInlinePolicyDynamicInlineDefault
    : public FunctionInlinePolicyBase<
          FunctionInlinePolicyDynamicInlineDefault> {
public:
  // inline by default
  // keep track of outlines, everything else is inline?
  std::set<uint64_t> range;
  FunctionInlineMode defaultMode;

  FunctionInlinePolicyDynamicInlineDefault() {
    defaultMode = FunctionInlineMode::INLINE;
  }

  FunctionInlinePolicyDynamicInlineDefault(
      FunctionInlinePolicyDynamicInlineDefault& other) {
    range = other.range;
    defaultMode = other.defaultMode;
  };

  FunctionInlinePolicyDynamicInlineDefault(
      FunctionInlinePolicyDynamicInlineDefault&& other) {
    range = std::move(other.range);
    defaultMode = std::move(other.defaultMode);
  };

  // void setDefaultMode_impl(FunctionInlineMode mode) { defaultMode = mode; }

  void addAddress_impl(uint64_t address) { range.insert(address); }

  FunctionInlineMode getAccessMode_impl(uint64_t address) const {
    auto it = range.upper_bound(address);
    if (it != range.begin()) {
      --it;
      if (address >= *it && address <= *it)
        return FunctionInlineMode::OUTLINE;
    }
    return this->defaultMode;
  }
};

// Dynamic mode, for when we need concolic execution
// outline by default
class FunctionInlinePolicyDynamicOutlineDefault
    : public FunctionInlinePolicyBase<
          FunctionInlinePolicyDynamicOutlineDefault> {
public:
  // inline by default
  // keep track of outlines, everything else is inline?
  std::set<uint64_t> range;
  FunctionInlineMode defaultMode;

  FunctionInlinePolicyDynamicOutlineDefault() {
    defaultMode = FunctionInlineMode::INLINE;
  }

  FunctionInlinePolicyDynamicOutlineDefault(
      FunctionInlinePolicyDynamicOutlineDefault& other) {
    range = other.range;
    defaultMode = other.defaultMode;
  };

  FunctionInlinePolicyDynamicOutlineDefault(
      FunctionInlinePolicyDynamicOutlineDefault&& other) {
    range = std::move(other.range);
    defaultMode = std::move(other.defaultMode);
  };

  // void setDefaultMode_impl(FunctionInlineMode mode) { defaultMode = mode; }

  void addAddress_impl(uint64_t address) { range.insert(address); }

  FunctionInlineMode getAccessMode_impl(uint64_t address) const {
    auto it = range.upper_bound(address);
    if (it != range.begin()) {
      --it;
      if (address >= *it && address <= *it)
        return FunctionInlineMode::OUTLINE;
    }
    return this->defaultMode;
  }
};

// Fully symbolic, for when we go fully symbolic with everything
class FunctionInlinePolicyInlineAll
    : public FunctionInlinePolicyBase<FunctionInlinePolicyInlineAll> {
public:
  FunctionInlinePolicyInlineAll() {}

  FunctionInlinePolicyInlineAll(FunctionInlinePolicyInlineAll& other){

  };

  FunctionInlinePolicyInlineAll(FunctionInlinePolicyInlineAll&& other){

  };

  void addAddress_impl(uint64_t start) { return; }

  FunctionInlineMode getAccessMode_impl(uint64_t address) const {
    return FunctionInlineMode::INLINE;
  }
};

// Fully concrete, could use it with emu
class FunctionInlinePolicyOutlineAll
    : public FunctionInlinePolicyBase<FunctionInlinePolicyOutlineAll> {
public:
  FunctionInlinePolicyOutlineAll() {}

  FunctionInlinePolicyOutlineAll(FunctionInlinePolicyOutlineAll& other){

  };

  FunctionInlinePolicyOutlineAll(FunctionInlinePolicyOutlineAll&& other){

  };

  void addAddress_impl(uint64_t start) { return; }

  FunctionInlineMode getAccessMode_impl(uint64_t address) const {
    return FunctionInlineMode::OUTLINE;
  }
};

using FunctionInlinePolicy = FunctionInlinePolicyDynamicInlineDefault;