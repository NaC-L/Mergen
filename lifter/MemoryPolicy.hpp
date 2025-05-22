#pragma once

#include <llvm/IR/Value.h>
#include <map>
#include <string>
#include <vector>
#include <memory>

namespace llvm {
class Module;
class Function;
}

enum class MemoryAccessMode {
    SYMBOLIC,
    CONCRETE
};

struct MemoryRange {
    uint64_t start;
    uint64_t end;
    MemoryAccessMode mode;
};

class MemoryPolicy {
private:
    MemoryAccessMode defaultMode;
    std::map<std::string, MemoryAccessMode> sectionPolicies;
    std::vector<MemoryRange> rangeOverrides;
    std::shared_ptr<llvm::Module> module;

public:
    MemoryPolicy(std::shared_ptr<llvm::Module> mod) : module(mod) {
        defaultMode = MemoryAccessMode::SYMBOLIC;
        sectionPolicies[".data"] = MemoryAccessMode::SYMBOLIC;
        sectionPolicies[".text"] = MemoryAccessMode::CONCRETE;
    }

    void setDefaultMode(MemoryAccessMode mode) {
        defaultMode = mode;
    }

    void addSectionPolicy(const std::string& section, MemoryAccessMode mode) {
        sectionPolicies[section] = mode;
    }

    void addRangeOverride(uint64_t start, uint64_t end, MemoryAccessMode mode) {
        rangeOverrides.push_back({start, end, mode});
    }

    MemoryAccessMode getAccessMode(uint64_t address) {
        for (const auto& range : rangeOverrides) {
            if (address >= range.start && address < range.end) {
                return range.mode;
            }
        }

        //then check section policies
        //this will require parsing ELF/PE headers to map addresses to sections? lmao
        //TODO: Implement section lookup based on address

        return defaultMode;
    }

    bool isSymbolic(uint64_t address) {
        return getAccessMode(address) == MemoryAccessMode::SYMBOLIC;
    }

    bool isConcrete(uint64_t address) {
        return getAccessMode(address) == MemoryAccessMode::CONCRETE;
    }
}; 