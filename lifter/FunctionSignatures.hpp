#ifndef FUNCSIGNATURES_H
#define FUNCSIGNATURES_H
#include "fileReader.hpp"
#include <iostream>
#include <map>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

// 8 << (arg.argtype.size - 1)
enum ArgType { NONE = 0, I8 = 1, I16 = 2, I32 = 3, I64 = 4 };

template <typename Register> class funcsignatures {
public:
  struct funcArgInfo {
    Register reg;

    struct argTypeInfo {
      uint8_t size : 4; // 4 bits for size
      uint8_t isPtr : 1;
      uint8_t pad : 3;
      argTypeInfo(ArgType type, bool isPtr)
          : size(static_cast<uint8_t>(type)), isPtr(isPtr ? 1 : 0), pad(0) {}
    } argtype;
    funcArgInfo(Register Reg, ArgType type, bool isPtr)
        : reg(Reg), argtype(type, isPtr){};
  };

  using funcArgInfos = std::vector<funcsignatures::funcArgInfo>;
  struct functioninfo {
    functioninfo() {}

    functioninfo(const std::string& Name) : name(Name) {}

    functioninfo(const std::string& Name, std::vector<funcArgInfo> Args)
        : name(Name), args(Args) {}

    functioninfo(const std::string& Name, const std::vector<funcArgInfo> Args,
                 const std::vector<unsigned char> Bytes)
        : name(Name), args(Args), bytes(Bytes) {}
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

    std::vector<unsigned char> bytes;
    // DS represents memory
    // (yeah i hate it aswell)
    // so the default is
    // rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15,memory
    // also
    // should SS represent stack ? (rsp+0x20 + (8 * arg) )
    // (SS is always ptr)
    static inline std::vector<uint64_t> offsets;
    static void add_offset(x86_64FileReader& file, uint64_t offset) {
      offsets.push_back(file.fileOffsetToRVA(offset));
    };
    void display() const {
      std::cout << "Function Name: " << name << ", Offsets: ";
      for (const auto& offset : offsets) {
        std::cout << offset << " ";
      }
      std::cout << "end" << std::endl;
    };
  };

  struct siginfo {
    siginfo(const std::vector<unsigned char>& Bytes);
    siginfo(const std::vector<unsigned char>& Bytes,
            const std::vector<unsigned char>& Args);

    std::vector<unsigned char> bytes;
    std::vector<unsigned char> args;
  };

  struct VectorHash {
    std::size_t operator()(const std::vector<unsigned char>& v) const {
      std::hash<unsigned char> hasher;
      std::size_t seed = 0;
      for (unsigned char i : v) {
        seed ^= hasher(i) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
      }
      return seed;
    }
  };

  class AhoCorasick {
  public:
    AhoCorasick(
        const std::unordered_map<std::vector<unsigned char>, functioninfo,
                                 VectorHash>& patterns_map) {
      trie.emplace_back();
      int id = 0;
      for (const auto& [pattern, _] : patterns_map) {
        int current = 0;
        for (unsigned char c : pattern) {
          if (trie[current].children.count(c) == 0) {
            trie[current].children[c] = trie.size();
            trie.emplace_back();
          }
          current = trie[current].children[c];
        }
        trie[current].output.push_back(id);
        patterns[id++] = pattern;
      }
      build();
    };

    std::vector<std::pair<int, int>>
    search(const std::vector<unsigned char>& text) {
      std::vector<std::pair<int, int>> results;
      int current = 0;
      for (uint64_t i = 0; i < text.size(); ++i) {
        while (current != -1 && trie[current].children.count(text[i]) == 0) {
          current = trie[current].fail;
        }
        if (current == -1) {
          current = 0;
          continue;
        }
        current = trie[current].children[text[i]];
        for (int id : trie[current].output) {
          results.emplace_back(i - patterns[id].size() + 1, id);
        }
      }
      return results;
    };

    struct Node {
      std::map<unsigned char, int> children;
      int fail = -1;
      std::vector<int> output;
    };

    std::vector<Node> trie;
    std::unordered_map<int, std::vector<unsigned char>> patterns;

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
          while (fail != -1 && trie[fail].children.count(c) == 0) {
            fail = trie[fail].fail;
          }
          if (fail != -1) {
            trie[next].fail = trie[fail].children[c];
          } else {
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

  static inline std::unordered_map<std::vector<unsigned char>, functioninfo,
                                   VectorHash>
      siglookup{
          {{0x55, 0x48, 0x81, 0xEC, 0xA0, 00, 00, 00, 0x48, 0x8D, 0xAC, 0x24,
            0x80, 00, 00, 00},
           functioninfo("??$?6U?$char_traits@D@std@@@std@@YAAEAV?$basic_"
                        "ostream@DU?$char_traits@D@std@@@0@AEAV10@PEBD@Z")},

          {{0x4C, 0x8B, 0xDC, 0x4D, 0x89, 0x43, 0x18, 0x4D, 0x89, 0x4B, 0x20,
            0x48, 0x83, 0xEC, 0x38},
           functioninfo("swprintf_s", {
                                          funcArgInfo(Register::RCX, I64, 1),
                                          funcArgInfo(Register::RDX, I64, 0),
                                          funcArgInfo(Register::R8, I64, 1),
                                          funcArgInfo(Register::R9, I64, 0),
                                      })}};

  static inline std::unordered_map<uint64_t, functioninfo> functions;
  static inline std::unordered_map<std::string, functioninfo> functionsByName{
      {"MessageBoxW", functioninfo("MessageBoxW",
                                   {
                                       funcArgInfo(Register::RCX, I64, 0),
                                       funcArgInfo(Register::RDX, I64, 1),
                                       funcArgInfo(Register::R8, I64, 1),
                                       funcArgInfo(Register::R9, I64, 0),
                                   })},
      {"GetTickCount64", functioninfo("GetTickCount64", {})},
  };
  ;

  static inline std::unordered_map<std::vector<unsigned char>, functioninfo,
                                   VectorHash>
  search_signatures(std::vector<unsigned char>& data) {
    x86_64FileReader file(data.data());
    AhoCorasick ac(siglookup);
    std::vector<std::pair<int, int>> matches = ac.search(data);
    for (const auto& [pos, id] : matches) {
      auto it = siglookup.find(ac.patterns[id]);
      if (it != siglookup.end()) {
        it->second.add_offset(file, pos);
      }
    }
    return siglookup;
  };

  std::vector<unsigned char> convertToVector(const unsigned char* data,
                                             size_t size) {
    return std::vector<unsigned char>(data, data + size);
  };

  static void createOffsetMap() {
    for (auto value : siglookup) {
      for (auto offsets : value.second.offsets) {
        functions[offsets] = value.second;
      }
      functionsByName[value.second.name] = value.second;
    }
  };
  static functioninfo* getFunctionInfo(uint64_t addr) {
    if (functions.count(addr) == 0)
      return nullptr;
    return &(functions[addr]);
  };

  static functioninfo* getFunctionInfo(const std::string& name) {
    if (functionsByName.count(name) == 0)
      return nullptr;
    return &(functionsByName[name]);
  };

}; // funcsignatures

#endif // FUNCSIGNATURES_H
