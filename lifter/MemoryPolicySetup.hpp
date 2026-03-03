#pragma once

#include "lifterClass_concolic.hpp"

inline void configureDefaultMemoryPolicy(lifterConcolic<>* lifter) {
  lifter->memoryPolicy.setDefaultMode(MemoryAccessMode::SYMBOLIC);

  for (auto& section : lifter->file.sections_v) {
    const auto sectionStart = lifter->file.imageBase + section.virtual_address;
    const auto sectionEnd = sectionStart + section.virtual_size;

    if (section.characteristics.mem_write) {
      lifter->memoryPolicy.addRange(sectionStart, sectionEnd,
                                    MemoryAccessMode::SYMBOLIC);
      continue;
    }

    lifter->memoryPolicy.addRange(sectionStart, sectionEnd,
                                  MemoryAccessMode::CONCRETE);
  }

  lifter->memoryPolicy.addRange(STACKP_VALUE - 0x1000, STACKP_VALUE + 0x1000,
                                MemoryAccessMode::CONCRETE);
}
