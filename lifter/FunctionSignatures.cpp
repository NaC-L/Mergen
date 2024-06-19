#include "FunctionSignatures.h"
#include "utils.h"
#include <algorithm>
#include <iostream>
#include <queue>

namespace funcsignatures {

    // replace functioninfo with std::string
    // so we can pass arguments
    std::unordered_map<uintptr_t, std::string> functions;

    void createOffsetMap() {
        for (auto value : siglookup) {
            for (auto offsets : value.second.offsets) {
                functions[offsets] = value.second.name;
            }
        }
    }

    std::string* getFunctionInfo(uintptr_t addr) {
        if (functions.count(addr) == 0)
            return nullptr;
        return &(functions[addr]);
    }

    functioninfo::functioninfo(const std::string& Name) : name(Name) {}

    void functioninfo::add_offset(uintptr_t offset) {
        offsets.push_back(FileHelper::fileOffsetToRVA(offset));
    }

    void functioninfo::display() const {
        std::cout << "Function Name: " << name << ", Offsets: ";
        for (const auto& offset : offsets) {
            std::cout << offset << " ";
        }
        std::cout << "end" << std::endl;
    }

    siginfo::siginfo(const std::vector<unsigned char>& Bytes) : bytes(Bytes) {}
    siginfo::siginfo(const std::vector<unsigned char>& Bytes,
                     const std::vector<unsigned char>& Args)
        : bytes(Bytes), args(Args) {}

    // dummy values
    std::unordered_map<std::vector<unsigned char>, functioninfo, VectorHash>
        siglookup{
            {{0x55, 0x48, 0x81, 0xEC, 0xA0, 00, 00, 00, 0x48, 0x8D, 0xAC, 0x24,
              0x80, 00, 00, 00},
             functioninfo("??$?6U?$char_traits@D@std@@@std@@YAAEAV?$basic_"
                          "ostream@DU?$char_traits@D@std@@@0@AEAV10@PEBD@Z")},

            {{0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10,
              0x48, 0x89, 0x70, 0x18, 0x48, 0x89, 0x78, 0x20, 0x41, 0x56, 0x48,
              0x81, 0xEC, 0xE0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x51, 0x08, 0x48,
              0x8B, 0xF2, 0x33, 0xD2, 0x4C, 0x8B, 0xF1, 0x48, 0x8D, 0x48, 0xA8,
              0x44, 0x8D, 0x42, 0x50, 0xE8, 0x7B, 0x0F, 0x00, 0x00},
             functioninfo("test2")}};

    AhoCorasick::AhoCorasick(
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
    }

    void AhoCorasick::build() {
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
    }

    std::vector<std::pair<int, int>>
    AhoCorasick::search(const std::vector<unsigned char>& text) {
        std::vector<std::pair<int, int>> results;
        int current = 0;
        for (int i = 0; i < text.size(); ++i) {
            while (current != -1 &&
                   trie[current].children.count(text[i]) == 0) {
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
    }

    std::unordered_map<std::vector<unsigned char>, functioninfo, VectorHash>
    search_signatures(const std::vector<unsigned char>& data) {
        AhoCorasick ac(siglookup);
        std::vector<std::pair<int, int>> matches = ac.search(data);
        for (const auto& [pos, id] : matches) {
            auto it = siglookup.find(ac.patterns[id]);
            if (it != siglookup.end()) {
                it->second.add_offset(pos);
            }
        }
        return siglookup;
    }

    std::vector<unsigned char> convertToVector(const unsigned char* data,
                                               size_t size) {
        return std::vector<unsigned char>(data, data + size);
    }
} // namespace funcsignatures
