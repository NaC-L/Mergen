#ifndef FUNCSIGNATURES_H
#define FUNCSIGNATURES_H
#include "includes.h"
#include <string>
#include <vector>

namespace funcsignatures {

  struct funcArgInfo {
    uint8_t reg;

    struct argTypeInfo {
      uint8_t size : 4; // 4 bits for size
      uint8_t isPtr : 1;
      uint8_t pad : 3;
      argTypeInfo(ArgType type, bool isPtr)
          : size(static_cast<uint8_t>(type)), isPtr(isPtr ? 1 : 0), pad(0) {}
    } argtype;
    funcArgInfo(uint8_t Reg, ArgType type, bool isPtr)
        : reg(Reg), argtype(type, isPtr) {};
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
    std::vector<unsigned char> bytes;
    std::string name;
    //
    funcArgInfos args = {funcArgInfo(ZYDIS_REGISTER_RAX, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_RCX, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_RDX, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_RBX, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_RSP, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_RBP, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_RSI, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_RDI, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_R8, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_R9, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_R10, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_R11, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_R12, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_R13, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_R14, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_R15, I64, 0),
                         funcArgInfo(ZYDIS_REGISTER_DS, I64, 1)};

    // DS represents memory
    // (yeah i hate it aswell)
    // so the default is
    // rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15,memory
    // also
    // should SS represent stack ? (rsp+0x20 + (8 * arg) )
    // (SS is always ptr)
    std::vector<uint64_t> offsets;
    void add_offset(uint64_t offset);
    void display() const;
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
                                 VectorHash>& patterns_map);
    std::vector<std::pair<int, int>>
    search(const std::vector<unsigned char>& text);

    struct Node {
      std::map<unsigned char, int> children;
      int fail = -1;
      std::vector<int> output;
    };

    std::vector<Node> trie;
    std::unordered_map<int, std::vector<unsigned char>> patterns;

    void build();
  };

  std::unordered_map<std::vector<unsigned char>, functioninfo, VectorHash>
  search_signatures(const std::vector<unsigned char>& data);
  std::vector<unsigned char> convertToVector(const unsigned char* data,
                                             size_t size);
  void createOffsetMap();
  functioninfo* getFunctionInfo(uint64_t addr);
  functioninfo* getFunctionInfo(std::string name);
  extern std::unordered_map<std::vector<unsigned char>, functioninfo,
                            VectorHash>
      siglookup;

} // namespace funcsignatures

#endif // FUNCSIGNATURES_H
