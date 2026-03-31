#ifndef FUNCSIGNATURES_H
#define FUNCSIGNATURES_H
#include "AbiCallContract.hpp"
#include "FileReader.hpp"
#include <array>
#include <cstddef>
#include <iostream>
#include <map>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

// 8 << (arg.argtype.size - 1) => I8/I16/I32/I64/I128
enum ArgType { NONE = 0, I8 = 1, I16 = 2, I32 = 3, I64 = 4, I128 = 5 };

template <typename Register> class funcsignatures {
public:
  struct funcArgInfo {
    Register reg;

    struct argTypeInfo {
      uint8_t size : 4; // 4 bits for size
      uint8_t isPtr : 1;
      uint8_t pad : 3;
      constexpr argTypeInfo(ArgType type, bool isPtr)
          : size(static_cast<uint8_t>(type)), isPtr(isPtr ? 1 : 0), pad(0) {}
    } argtype;
    constexpr funcArgInfo(Register Reg, ArgType type, bool isPtr)
        : reg(Reg), argtype(type, isPtr){};
  };

  using funcArgInfos = std::vector<funcsignatures::funcArgInfo>;
  struct functioninfo {
    functioninfo() {}

    functioninfo(const std::string& Name) : name(Name) {}

    functioninfo(const std::string& Name, std::vector<funcArgInfo> Args)
        : name(Name), args(Args) {}
    std::string name;
    //
    funcArgInfos args = {
        funcArgInfo(Register::RAX, I64, 0), funcArgInfo(Register::RCX, I64, 0),
        funcArgInfo(Register::RDX, I64, 0), funcArgInfo(Register::RBX, I64, 0),
        funcArgInfo(Register::RSP, I64, 0), funcArgInfo(Register::RBP, I64, 0),
        funcArgInfo(Register::RSI, I64, 0), funcArgInfo(Register::RDI, I64, 0),
        funcArgInfo(Register::R8, I64, 0),  funcArgInfo(Register::R9, I64, 0),
        funcArgInfo(Register::R10, I64, 0), funcArgInfo(Register::R11, I64, 0),
        funcArgInfo(Register::R12, I64, 0), funcArgInfo(Register::R13, I64, 0),
        funcArgInfo(Register::R14, I64, 0), funcArgInfo(Register::R15, I64, 0),
        funcArgInfo(Register::DS, I64, 1)};

    // ABI metadata (optional). Default values preserve backward compatibility.
    AbiKind      abiKind      = AbiKind::Unknown;
    StackCleanup stackCleanup = StackCleanup::Unknown;
    // DS represents memory
    // (yeah i hate it aswell)
    // so the default is
    // rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15,memory
    // also
    // should SS represent stack ? (rsp+0x20 + (8 * arg) )
    // (SS is always ptr)
  };

private:
  struct SignatureSpec {
    const char*        name;
    const unsigned char* bytes;
    size_t             byteCount;
    const funcArgInfo* args;
    size_t             argCount;
  };

  class AhoCorasick {
  public:
    template <size_t N>
    explicit AhoCorasick(const std::array<SignatureSpec, N>& specs) {
      trie.emplace_back();
      patternLengths.reserve(N);
      for (size_t id = 0; id < N; ++id) {
        const auto& spec = specs[id];
        int current = 0;
        for (size_t i = 0; i < spec.byteCount; ++i) {
          const unsigned char c = spec.bytes[i];
          auto childIt = trie[current].children.find(c);
          if (childIt == trie[current].children.end()) {
            trie[current].children[c] = static_cast<int>(trie.size());
            trie.emplace_back();
            current = static_cast<int>(trie.size()) - 1;
          } else {
            current = childIt->second;
          }
        }
        trie[current].output.push_back(id);
        patternLengths.push_back(spec.byteCount);
      }
      build();
    };

    std::vector<std::pair<uint64_t, size_t>>
    search(const std::vector<unsigned char>& text) const {
      std::vector<std::pair<uint64_t, size_t>> results;
      int current = 0;
      for (uint64_t i = 0; i < text.size(); ++i) {
        const unsigned char c = text[i];
        while (current != -1) {
          auto childIt = trie[current].children.find(c);
          if (childIt != trie[current].children.end()) {
            current = childIt->second;
            break;
          }
          current = trie[current].fail;
        }
        if (current == -1) {
          current = 0;
          continue;
        }
        for (size_t id : trie[current].output) {
          results.emplace_back(i - patternLengths[id] + 1, id);
        }
      }
      return results;
    };

    struct Node {
      std::map<unsigned char, int> children;
      int fail = -1;
      std::vector<size_t> output;
    };

    std::vector<Node> trie;
    std::vector<size_t> patternLengths;

    void build() {
      std::queue<int> q;
      for (const auto& [c, next] : trie[0].children) {
        trie[next].fail = 0;
        q.push(next);
      }
      while (!q.empty()) {
        int current = q.front();
        q.pop();
        for (const auto& [c, next] : trie[current].children) {
          int fail = trie[current].fail;
          while (fail != -1) {
            auto failIt = trie[fail].children.find(c);
            if (failIt != trie[fail].children.end()) {
              trie[next].fail = failIt->second;
              break;
            }
            fail = trie[fail].fail;
          }
          if (fail == -1) {
            trie[next].fail = 0;
          }
          trie[next].output.insert(trie[next].output.end(),
                                   trie[trie[next].fail].output.begin(),
                                   trie[trie[next].fail].output.end());
          q.push(next);
        }
      }
    };
  };

  static inline constexpr std::array<unsigned char, 16> kOstreamBytes = {
      0x55, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00,
      0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00};

  static inline constexpr std::array<unsigned char, 15> kSwprintfBytes = {
      0x4C, 0x8B, 0xDC, 0x4D, 0x89, 0x43, 0x18,
      0x4D, 0x89, 0x4B, 0x20, 0x48, 0x83, 0xEC, 0x38};

  static inline constexpr std::array<funcArgInfo, 4> kSwprintfArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I64, 1),
      funcArgInfo(Register::R9, I64, 0),
  };

  static inline constexpr std::array<SignatureSpec, 2> kBinarySignatureSpecs = {{
      {"??$?6U?$char_traits@D@std@@@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@0@AEAV10@PEBD@Z",
       kOstreamBytes.data(), kOstreamBytes.size(), nullptr, 0},
      {"swprintf_s", kSwprintfBytes.data(), kSwprintfBytes.size(),
       kSwprintfArgs.data(), kSwprintfArgs.size()},
  }};

  static functioninfo buildFunctionInfo(const SignatureSpec& spec) {
    if (spec.argCount == 0) {
      return functioninfo(spec.name);
    }

    funcArgInfos args;
    args.reserve(spec.argCount);
    for (size_t i = 0; i < spec.argCount; ++i) {
      args.push_back(spec.args[i]);
    }
    return functioninfo(spec.name, args);
  }

  static const AhoCorasick& getBinarySignatureMatcher() {
    static const AhoCorasick matcher(kBinarySignatureSpecs);
    return matcher;
  }

public:
  static inline std::unordered_map<uint64_t, functioninfo> functions;
  static inline std::unordered_map<std::string, std::vector<uint64_t>>
      signatureOffsets;

  // Known Win32 API signatures for named import call emission.
  // Only register-passed arguments (RCX, RDX, R8, R9) are modeled;
  // stack-passed arguments (5th+ params) are not yet supported.
  // Functions with >4 params emit declarations for the first 4 only.
  static inline constexpr std::array<funcArgInfo, 4> kMessageBoxArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
      funcArgInfo(Register::R8, I64, 1),
      funcArgInfo(Register::R9, I64, 0),
  };
  static inline constexpr std::array<funcArgInfo, 1> kQueryCounterArgs = {
      funcArgInfo(Register::RCX, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 1> kSleepArgs = {
      funcArgInfo(Register::RCX, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 4> kVirtualAllocArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 3> kVirtualFreeArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 4> kVirtualProtectArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 3> kHeapAllocArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I32, 0),
      funcArgInfo(Register::R8, I64, 0),
  };
  static inline constexpr std::array<funcArgInfo, 3> kHeapFreeArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I32, 0),
      funcArgInfo(Register::R8, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 4> kCreateFileArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I32, 0),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 4> kReadWriteFileArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 1> kCloseHandleArgs = {
      funcArgInfo(Register::RCX, I64, 0),
  };
  static inline constexpr std::array<funcArgInfo, 1> kModuleHandleArgs = {
      funcArgInfo(Register::RCX, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 2> kGetProcAddressArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
  };
  static inline constexpr std::array<funcArgInfo, 3> kLoadLibraryExWArgs = {
      funcArgInfo(Register::RCX, I64, 1),
      funcArgInfo(Register::RDX, I64, 0),
      funcArgInfo(Register::R8, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 1> kExitProcessArgs = {
      funcArgInfo(Register::RCX, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 2> kWaitForSingleObjectArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 4> kRegOpenKeyExWArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
      funcArgInfo(Register::R8, I32, 0),
      funcArgInfo(Register::R9, I32, 0),
  };
  static inline constexpr std::array<funcArgInfo, 4> kRegQueryValueExWArgs = {
      funcArgInfo(Register::RCX, I64, 0),
      funcArgInfo(Register::RDX, I64, 1),
      funcArgInfo(Register::R8, I64, 1),
      funcArgInfo(Register::R9, I64, 1),
  };

  static inline constexpr std::array<SignatureSpec, 33> kNamedFunctionSpecs = {{
      {"MessageBoxW", nullptr, 0, kMessageBoxArgs.data(), kMessageBoxArgs.size()},
      {"MessageBoxA", nullptr, 0, kMessageBoxArgs.data(), kMessageBoxArgs.size()},
      {"GetTickCount64", nullptr, 0, nullptr, 0},
      {"GetTickCount", nullptr, 0, nullptr, 0},
      {"QueryPerformanceCounter", nullptr, 0, kQueryCounterArgs.data(), kQueryCounterArgs.size()},
      {"QueryPerformanceFrequency", nullptr, 0, kQueryCounterArgs.data(), kQueryCounterArgs.size()},
      {"Sleep", nullptr, 0, kSleepArgs.data(), kSleepArgs.size()},
      {"VirtualAlloc", nullptr, 0, kVirtualAllocArgs.data(), kVirtualAllocArgs.size()},
      {"VirtualFree", nullptr, 0, kVirtualFreeArgs.data(), kVirtualFreeArgs.size()},
      {"VirtualProtect", nullptr, 0, kVirtualProtectArgs.data(), kVirtualProtectArgs.size()},
      {"HeapAlloc", nullptr, 0, kHeapAllocArgs.data(), kHeapAllocArgs.size()},
      {"HeapFree", nullptr, 0, kHeapFreeArgs.data(), kHeapFreeArgs.size()},
      {"CreateFileW", nullptr, 0, kCreateFileArgs.data(), kCreateFileArgs.size()},
      {"CreateFileA", nullptr, 0, kCreateFileArgs.data(), kCreateFileArgs.size()},
      {"ReadFile", nullptr, 0, kReadWriteFileArgs.data(), kReadWriteFileArgs.size()},
      {"WriteFile", nullptr, 0, kReadWriteFileArgs.data(), kReadWriteFileArgs.size()},
      {"CloseHandle", nullptr, 0, kCloseHandleArgs.data(), kCloseHandleArgs.size()},
      {"GetCurrentProcess", nullptr, 0, nullptr, 0},
      {"GetCurrentProcessId", nullptr, 0, nullptr, 0},
      {"GetCurrentThreadId", nullptr, 0, nullptr, 0},
      {"GetModuleHandleW", nullptr, 0, kModuleHandleArgs.data(), kModuleHandleArgs.size()},
      {"GetModuleHandleA", nullptr, 0, kModuleHandleArgs.data(), kModuleHandleArgs.size()},
      {"GetProcAddress", nullptr, 0, kGetProcAddressArgs.data(), kGetProcAddressArgs.size()},
      {"LoadLibraryW", nullptr, 0, kModuleHandleArgs.data(), kModuleHandleArgs.size()},
      {"LoadLibraryA", nullptr, 0, kModuleHandleArgs.data(), kModuleHandleArgs.size()},
      {"LoadLibraryExW", nullptr, 0, kLoadLibraryExWArgs.data(), kLoadLibraryExWArgs.size()},
      {"ExitProcess", nullptr, 0, kExitProcessArgs.data(), kExitProcessArgs.size()},
      {"GetLastError", nullptr, 0, nullptr, 0},
      {"SetLastError", nullptr, 0, kExitProcessArgs.data(), kExitProcessArgs.size()},
      {"WaitForSingleObject", nullptr, 0, kWaitForSingleObjectArgs.data(), kWaitForSingleObjectArgs.size()},
      {"RegOpenKeyExW", nullptr, 0, kRegOpenKeyExWArgs.data(), kRegOpenKeyExWArgs.size()},
      {"RegQueryValueExW", nullptr, 0, kRegQueryValueExWArgs.data(), kRegQueryValueExWArgs.size()},
      {"RegCloseKey", nullptr, 0, kCloseHandleArgs.data(), kCloseHandleArgs.size()},
  }};

  static std::unordered_map<std::string, functioninfo>& getNamedFunctionsByName() {
    static std::unordered_map<std::string, functioninfo> functionsByName = []() {
      std::unordered_map<std::string, functioninfo> map;
      map.reserve(kNamedFunctionSpecs.size());
      for (const auto& spec : kNamedFunctionSpecs) {
        map.emplace(spec.name, buildFunctionInfo(spec));
      }
      return map;
    }();
    return functionsByName;
  }

  static void search_signatures(std::vector<unsigned char>& data) {
    signatureOffsets.clear();
    if (data.empty()) {
      return;
    }

    x86_64FileReader file(data.data());
    const auto& matcher = getBinarySignatureMatcher();
    std::vector<std::pair<uint64_t, size_t>> matches = matcher.search(data);
    for (const auto& [pos, id] : matches) {
      const auto& spec = kBinarySignatureSpecs[id];
      signatureOffsets[spec.name].push_back(file.fileOffsetToRVA(pos));
    }
  };

  static void createOffsetMap() {
    functions.clear();
    for (const auto& spec : kBinarySignatureSpecs) {
      auto it = signatureOffsets.find(spec.name);
      if (it == signatureOffsets.end())
        continue;

      functioninfo info = buildFunctionInfo(spec);
      for (const auto offset : it->second) {
        functions[offset] = info;
      }
    }
  };

  static void displayMatches() {
    for (const auto& spec : kBinarySignatureSpecs) {
      std::cout << "Function Name: " << spec.name << ", Offsets: ";
      auto it = signatureOffsets.find(spec.name);
      if (it != signatureOffsets.end()) {
        for (const auto& offset : it->second) {
          std::cout << offset << " ";
        }
      }
      std::cout << "end" << std::endl;
    }
  }

  static functioninfo* getFunctionInfo(uint64_t addr) {
    auto it = functions.find(addr);
    if (it == functions.end())
      return nullptr;
    return &it->second;
  };

  static functioninfo* getFunctionInfo(const std::string& name) {
    auto& functionsByName = getNamedFunctionsByName();
    auto it = functionsByName.find(name);
    if (it == functionsByName.end())
      return nullptr;
    return &it->second;
  };
}; // funcsignatures

#endif // FUNCSIGNATURES_H
