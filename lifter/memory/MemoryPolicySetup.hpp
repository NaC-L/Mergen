#pragma once

#include "LifterClass_Concolic.hpp"

inline void configureDefaultMemoryPolicy(lifterConcolic<>* lifter) {
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

  lifter->memoryPolicy.addRange(STACKP_VALUE - 0x1000, STACKP_VALUE + 0x1000,
                                MemoryAccessMode::CONCRETE);
}
