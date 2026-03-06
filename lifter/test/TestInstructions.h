#pragma once

#include <cstdint>
#include <string>

int testInit(const std::string& suiteFilter = "");
int buildFullHandlerSeed(const std::string& outputPath,
                         const std::string& opcodePath = "lifter/semantics/x86_64_opcodes.x",
                         uint64_t maxAttempts = 2'500'000,
                         uint64_t randomSeed = 1337);
