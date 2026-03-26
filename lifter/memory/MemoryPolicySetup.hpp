#pragma once

#include "LifterClass_Concolic.hpp"
#include <algorithm>
#include <cstdint>

inline void configureDefaultMemoryPolicy(lifterConcolic<>* lifter,
                                         uint64_t stackReserve = 0x1000) {
  lifter->memoryPolicy.setDefaultMode(MemoryAccessMode::SYMBOLIC);

  for (auto& section : lifter->file.sections_v) {
    const auto sectionStart = lifter->file.imageBase + section.virtual_address;
    const auto sectionEnd = sectionStart + section.virtual_size;

    // All PE sections are CONCRETE: initial values are known from the file.
    // The concolic buffer tracks stores, so reads without prior stores
    // correctly return the file's initial bytes.
    lifter->memoryPolicy.addRange(sectionStart, sectionEnd,
                                  MemoryAccessMode::CONCRETE);
  }

  // Use actual stack reserve from PE header instead of hardcoded 0x1000.
  // Clamp to reasonable bounds: at least 0x1000, at most 0x100000 (1MB).
  uint64_t clampedReserve = std::max(stackReserve, uint64_t(0x1000));
  clampedReserve = std::min(clampedReserve, uint64_t(0x100000));
  lifter->stackReserve = clampedReserve;
  lifter->memoryPolicy.addRange(STACKP_VALUE - clampedReserve,
                                STACKP_VALUE + clampedReserve,
                                MemoryAccessMode::CONCRETE);
}
