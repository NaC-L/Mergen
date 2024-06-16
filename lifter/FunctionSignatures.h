#ifndef FUNCSIGNATURES_H
#define FUNCSIGNATURES_H

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace funcsignatures {

    struct functioninfo {
        functioninfo(const std::string& Name);
        std::string name;
        std::vector<uintptr_t> offsets;

        void add_offset(uintptr_t offset);
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

    extern std::unordered_map<std::vector<unsigned char>, functioninfo,
                              VectorHash>
        siglookup;

} // namespace funcsignatures

#endif // FUNCSIGNATURES_H
