#include "TestInstructions.h"

#ifdef MERGEN_TEST

#include "Tester.hpp"

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

using HandlerMnemonicMap = std::unordered_map<std::string, std::vector<std::string>>;
using MnemonicSampleMap = std::unordered_map<std::string, std::vector<uint8_t>>;

struct ManualCaseSpec {
  std::string mnemonic;
  std::vector<uint8_t> instructionBytes;
  std::vector<RegisterState> initialRegisters;
  std::vector<FlagStatus> initialFlags;
};

const std::unordered_map<std::string, std::string> kMnemonicAliases = {
    {"jae", "jnb"},       {"jnae", "jb"},      {"jna", "jbe"},
    {"ja", "jnbe"},       {"jnge", "jl"},      {"jge", "jnl"},
    {"jg", "jnle"},       {"jng", "jle"},      {"jpe", "jp"},
    {"jpo", "jnp"},       {"setae", "setnb"},  {"setna", "setbe"},
    {"seta", "setnbe"},   {"setge", "setnl"},  {"setg", "setnle"},
    {"setpe", "setp"},    {"setpo", "setnp"},  {"cmovae", "cmovnb"},
    {"cmovna", "cmovbe"}, {"cmova", "cmovnbe"}, {"cmovge", "cmovnl"},
    {"cmovg", "cmovnle"}, {"cmovpe", "cmovp"}, {"cmovpo", "cmovnp"},
};

RegisterState makeRegisterState(RegisterUnderTest reg, uint64_t value) {
  return RegisterState{
      .reg = reg,
      .value = llvm::APInt(getRegisterSize(reg), value, false),
  };
}

std::string formatAPIntHex(const llvm::APInt& value) {
  llvm::SmallString<64> formatted;
  value.toString(formatted, 16, false);
  return "0x" + std::string(formatted);
}

const std::unordered_map<std::string, ManualCaseSpec> kManualHandlerCases = {
    {"imul2",
     ManualCaseSpec{.mnemonic = "imul",
                    .instructionBytes = {0x48, 0xF7, 0xE9},
                    .initialRegisters = {makeRegisterState(RegisterUnderTest::RAX, 7),
                                         makeRegisterState(RegisterUnderTest::RDX, 0),
                                         makeRegisterState(RegisterUnderTest::RCX, 3)},
                    .initialFlags = {}}},
    {"mul2",
     ManualCaseSpec{.mnemonic = "mul",
                    .instructionBytes = {0x48, 0xF7, 0xE1},
                    .initialRegisters = {makeRegisterState(RegisterUnderTest::RAX, 7),
                                         makeRegisterState(RegisterUnderTest::RDX, 0),
                                         makeRegisterState(RegisterUnderTest::RCX, 3)},
                    .initialFlags = {}}},
    {"div2",
     ManualCaseSpec{.mnemonic = "div",
                    .instructionBytes = {0x48, 0xF7, 0xF1},
                    .initialRegisters = {makeRegisterState(RegisterUnderTest::RAX, 16),
                                         makeRegisterState(RegisterUnderTest::RDX, 0),
                                         makeRegisterState(RegisterUnderTest::RCX, 2)},
                    .initialFlags = {}}},
    {"idiv2",
     ManualCaseSpec{.mnemonic = "idiv",
                    .instructionBytes = {0x48, 0xF7, 0xF9},
                    .initialRegisters = {makeRegisterState(RegisterUnderTest::RAX, 16),
                                         makeRegisterState(RegisterUnderTest::RDX, 0),
                                         makeRegisterState(RegisterUnderTest::RCX, 2)},
                    .initialFlags = {}}},
};

const std::vector<RegisterState> kDefaultInitialRegisters = {
    makeRegisterState(RegisterUnderTest::RAX, 0x1122334455667788ULL),
    makeRegisterState(RegisterUnderTest::RBX, 0x8877665544332211ULL),
    makeRegisterState(RegisterUnderTest::RCX, 0x10ULL),
    makeRegisterState(RegisterUnderTest::RDX, 0x2ULL),
};

std::string trim(const std::string& value) {
  size_t start = 0;
  while (start < value.size() &&
         std::isspace(static_cast<unsigned char>(value[start]))) {
    ++start;
  }

  size_t end = value.size();
  while (end > start &&
         std::isspace(static_cast<unsigned char>(value[end - 1]))) {
    --end;
  }

  return value.substr(start, end - start);
}

std::string toLower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::string normalizeMnemonic(std::string mnemonic) {
  mnemonic = toLower(std::move(mnemonic));
  auto alias = kMnemonicAliases.find(mnemonic);
  if (alias != kMnemonicAliases.end()) {
    return alias->second;
  }
  return mnemonic;
}

bool readTextFile(const std::string& path, std::string& outText) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    return false;
  }

  std::ostringstream oss;
  oss << ifs.rdbuf();
  outText = oss.str();
  return true;
}

std::string stripOpcodeComments(const std::string& text) {
  std::string noBlock =
      std::regex_replace(text, std::regex(R"(/\*[\s\S]*?\*/)", std::regex::ECMAScript),
                         "");
  return std::regex_replace(noBlock,
                            std::regex(R"(//[^\n\r]*)", std::regex::ECMAScript),
                            "");
}

HandlerMnemonicMap parseOpcodeHandlers(const std::string& opcodePath,
                                       std::string& outError) {
  std::string text;
  if (!readTextFile(opcodePath, text)) {
    outError = "failed to read opcode file: " + opcodePath;
    return {};
  }

  text = stripOpcodeComments(text);

  HandlerMnemonicMap handlers;
  std::regex opcodeRegex(R"(OPCODE\(([^)]*)\))", std::regex::ECMAScript);
  auto begin = std::sregex_iterator(text.begin(), text.end(), opcodeRegex);
  auto end = std::sregex_iterator();

  for (auto it = begin; it != end; ++it) {
    std::string body = (*it)[1].str();

    std::vector<std::string> tokens;
    std::stringstream ss(body);
    std::string token;
    while (std::getline(ss, token, ',')) {
      token = trim(token);
      if (!token.empty()) {
        tokens.push_back(token);
      }
    }

    if (tokens.empty()) {
      continue;
    }

    const std::string handler = toLower(tokens[0]);
    std::vector<std::string> mnemonics;
    for (size_t i = 1; i < tokens.size(); ++i) {
      mnemonics.push_back(toLower(tokens[i]));
    }

    handlers[handler] = std::move(mnemonics);
  }

  return handlers;
}

std::optional<std::string> decodeMnemonicFromCandidate(
    LifterUnderTest& lifter, const std::array<uint8_t, 15>& candidate,
    std::vector<uint8_t>& outInstructionBytes) {
  lifter.runDisassembler(candidate.data(), candidate.size());
  if (lifter.instruction.length == 0 || lifter.instruction.length > candidate.size()) {
    return std::nullopt;
  }

  std::string rawMnemonic =
      std::string(magic_enum::enum_name(lifter.instruction.mnemonic));
  if (rawMnemonic.empty()) {
    return std::nullopt;
  }

  std::string normalized = normalizeMnemonic(rawMnemonic);
  if (normalized == "invalid" || normalized == "none") {
    return std::nullopt;
  }

  outInstructionBytes.assign(candidate.begin(),
                             candidate.begin() + lifter.instruction.length);
  return normalized;
}

MnemonicSampleMap discoverMnemonicSamples(const std::unordered_set<std::string>& targets,
                                          uint64_t maxAttempts,
                                          uint64_t randomSeed) {
  MnemonicSampleMap samples;
  if (targets.empty()) {
    return samples;
  }

  std::mt19937_64 rng(randomSeed);
  std::uniform_int_distribution<uint16_t> byteDist(0, 0xFF);
  std::vector<uint8_t> safeLeadBytes;
  safeLeadBytes.reserve(256);
  const std::unordered_set<uint8_t> excludedLeadBytes = {
      0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3};
  for (uint16_t value = 0; value <= 0xFF; ++value) {
    const uint8_t byte = static_cast<uint8_t>(value);
    if (byte >= 0xD8 && byte <= 0xDF) {
      continue;
    }
    if (excludedLeadBytes.contains(byte)) {
      continue;
    }
    safeLeadBytes.push_back(byte);
  }
  std::uniform_int_distribution<size_t> leadByteDist(0, safeLeadBytes.size() - 1);

  LifterUnderTest lifter;
  std::array<uint8_t, 15> candidate{};
  std::vector<uint8_t> decodedBytes;

  for (uint64_t attempt = 0;
       attempt < maxAttempts && samples.size() < targets.size(); ++attempt) {
    candidate.fill(0);
    candidate[0] = safeLeadBytes[leadByteDist(rng)];
    candidate[1] = static_cast<uint8_t>(byteDist(rng));
    candidate[2] = static_cast<uint8_t>(byteDist(rng));
    candidate[3] = static_cast<uint8_t>(byteDist(rng));

    auto mnemonic = decodeMnemonicFromCandidate(lifter, candidate, decodedBytes);
    if (!mnemonic.has_value()) {
      continue;
    }

    if (!targets.contains(*mnemonic)) {
      continue;
    }

    if (!samples.contains(*mnemonic)) {
      samples[*mnemonic] = decodedBytes;
    }
  }

  return samples;
}

InstructionTestCase buildSmokeCase(const std::string& handler,
                                   const std::string& mnemonic,
                                   const std::vector<uint8_t>& bytes,
                                   const std::vector<RegisterState>& initialRegs,
                                   const std::vector<FlagStatus>& initialFlags) {
  return InstructionTestCase{
      .name = "smoke_" + handler + "_" + mnemonic,
      .instructionBytes = bytes,
      .initialRegisters = initialRegs,
      .initialFlags = initialFlags,
      .expectedRegisters = {},
      .expectedFlags = {},
  };
}

llvm::json::Object toJsonCase(const InstructionTestCase& testCase,
                              const std::string& handler) {
  llvm::json::Array byteArray;
  for (uint8_t byte : testCase.instructionBytes) {
    byteArray.push_back(static_cast<int64_t>(byte));
  }

  llvm::json::Object initialRegs;
  for (const auto& reg : testCase.initialRegisters) {
    initialRegs[std::string(magic_enum::enum_name(reg.reg))] =
        formatAPIntHex(reg.value);
  }

  llvm::json::Object initialFlags;
  for (const auto& flag : testCase.initialFlags) {
    initialFlags[std::string(magic_enum::enum_name(flag.flag))] =
        flag.value ? 1 : 0;
  }

  llvm::json::Object initial;
  initial["registers"] = std::move(initialRegs);
  initial["flags"] = std::move(initialFlags);

  llvm::json::Object expected;
  expected["registers"] = llvm::json::Object{};
  expected["flags"] = llvm::json::Object{};

  llvm::json::Object out;
  out["name"] = testCase.name;
  out["handler"] = handler;
  out["instruction_bytes"] = std::move(byteArray);
  out["initial"] = std::move(initial);
  out["expected"] = std::move(expected);
  out["oracle"] = "none";
  out["source"] = "auto-discovery";
  return out;
}

bool writeTextFile(const std::string& path, const std::string& content) {
  std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
  if (!ofs.is_open()) {
    return false;
  }
  ofs << content;
  return ofs.good();
}

bool parseU64Literal(const llvm::json::Value& value, uint64_t& out) {
  if (auto integerValue = value.getAsInteger()) {
    if (*integerValue < 0) {
      return false;
    }
    out = static_cast<uint64_t>(*integerValue);
    return true;
  }

  if (auto stringValue = value.getAsString()) {
    try {
      std::string raw = std::string(*stringValue);
      size_t parsed = 0;
      out = std::stoull(raw, &parsed, 0);
      return parsed == raw.size();
    } catch (...) {
      return false;
    }
  }

  return false;
}

bool parseAPIntLiteral(const llvm::json::Value& value, unsigned bitWidth,
                       llvm::APInt& out) {
  if (bitWidth == 0) {
    return false;
  }

  if (auto integerValue = value.getAsInteger()) {
    if (*integerValue < 0) {
      return false;
    }

    const uint64_t rawValue = static_cast<uint64_t>(*integerValue);
    if (bitWidth < 64 && (rawValue >> bitWidth) != 0) {
      return false;
    }

    out = llvm::APInt(bitWidth, rawValue, false);
    return true;
  }

  if (auto stringValue = value.getAsString()) {
    std::string raw = trim(std::string(*stringValue));
    if (raw.empty() || raw[0] == '-') {
      return false;
    }

    unsigned radix = 10;
    if (raw.size() > 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X')) {
      radix = 16;
      raw = raw.substr(2);
    }

    if (raw.empty()) {
      return false;
    }

    const std::string validChars =
        radix == 16 ? "0123456789abcdefABCDEF" : "0123456789";
    if (raw.find_first_not_of(validChars) != std::string::npos) {
      return false;
    }

    const unsigned parseWidth =
        std::max<unsigned>(bitWidth, static_cast<unsigned>(raw.size() * 4 + 1));
    llvm::APInt parsed(parseWidth, raw, radix);
    if (parsed.getActiveBits() > bitWidth) {
      return false;
    }

    out = parsed.zextOrTrunc(bitWidth);
    return true;
  }

  return false;
}

bool parseBoolLike(const llvm::json::Value& value, bool& out) {
  if (auto booleanValue = value.getAsBoolean()) {
    out = *booleanValue;
    return true;
  }

  uint64_t numeric = 0;
  if (!parseU64Literal(value, numeric)) {
    return false;
  }

  out = numeric != 0;
  return true;
}

std::optional<RegisterUnderTest> parseRegisterName(llvm::StringRef name) {
  auto parsed = magic_enum::enum_cast<RegisterUnderTest>(name.str());
  if (!parsed.has_value()) {
    return std::nullopt;
  }
  return parsed.value();
}

std::optional<Flag> parseFlagName(llvm::StringRef name) {
  auto parsed = magic_enum::enum_cast<Flag>(name.str());
  if (!parsed.has_value()) {
    return std::nullopt;
  }
  return parsed.value();
}

bool parseInstructionBytes(const llvm::json::Array* bytesArray,
                           std::vector<uint8_t>& outBytes,
                           std::string& outError) {
  outBytes.clear();
  for (const auto& entry : *bytesArray) {
    uint64_t byteValue = 0;
    if (!parseU64Literal(entry, byteValue) || byteValue > 0xFF) {
      outError = "instruction_bytes contains non-byte value";
      return false;
    }
    outBytes.push_back(static_cast<uint8_t>(byteValue));
  }

  if (outBytes.empty()) {
    outError = "instruction_bytes is empty";
    return false;
  }

  return true;
}

bool parseRegisterMap(const llvm::json::Object* registerObject,
                      std::vector<RegisterState>& outRegisters,
                      std::string& outError) {
  outRegisters.clear();
  if (!registerObject) {
    return true;
  }

  for (const auto& [name, rawValue] : *registerObject) {
    auto reg = parseRegisterName(name);
    if (!reg.has_value()) {
      outError = "unknown register: " + name.str();
      return false;
    }

    const auto bitWidth = static_cast<unsigned>(getRegisterSize(reg.value()));
    llvm::APInt value(bitWidth, 0, false);
    if (!parseAPIntLiteral(rawValue, bitWidth, value)) {
      outError = "invalid register value for " + name.str();
      return false;
    }

    outRegisters.push_back(
        RegisterState{.reg = reg.value(), .value = std::move(value)});
  }

  return true;
}

bool parseFlagMap(const llvm::json::Object* flagObject,
                  std::vector<FlagStatus>& outFlags,
                  std::string& outError) {
  outFlags.clear();
  if (!flagObject) {
    return true;
  }

  for (const auto& [name, rawValue] : *flagObject) {
    auto flag = parseFlagName(name);
    if (!flag.has_value()) {
      outError = "unknown flag: " + name.str();
      return false;
    }

    bool value = false;
    if (!parseBoolLike(rawValue, value)) {
      outError = "invalid flag value for " + name.str();
      return false;
    }

    outFlags.push_back(FlagStatus{.flag = flag.value(), .value = value});
  }

  return true;
}

bool loadOracleCases(const std::string& oraclePath,
                     std::vector<InstructionTestCase>& outCases,
                     std::string& outError) {
  outCases.clear();

  auto bufferOrErr = llvm::MemoryBuffer::getFile(oraclePath);
  if (!bufferOrErr) {
    outError = "failed to read oracle vectors file: " + oraclePath;
    return false;
  }

  auto parsed = llvm::json::parse(bufferOrErr.get()->getBuffer());
  if (!parsed) {
    outError = "oracle vectors JSON parse failed";
    return false;
  }

  const auto* root = parsed->getAsObject();
  if (!root) {
    outError = "oracle vectors root is not an object";
    return false;
  }

  auto schema = root->getString("schema");
  if (!schema || *schema != "mergen-oracle-v1") {
    outError = "oracle vectors schema mismatch";
    return false;
  }

  const auto* cases = root->getArray("cases");
  if (!cases || cases->empty()) {
    outError = "oracle vectors has no cases";
    return false;
  }

  for (const auto& caseValue : *cases) {
    const auto* caseObject = caseValue.getAsObject();
    if (!caseObject) {
      outError = "case entry is not an object";
      return false;
    }

    if (auto skipCase = caseObject->getBoolean("skip"); skipCase && *skipCase) {
      continue;
    }

    auto caseName = caseObject->getString("name");
    auto bytesArray = caseObject->getArray("instruction_bytes");
    const auto* expectedObject = caseObject->getObject("expected");

    if (!caseName || !bytesArray || !expectedObject) {
      outError = "case missing required fields (name/instruction_bytes/expected)";
      return false;
    }

    InstructionTestCase testCase;
    testCase.name = std::string(*caseName);

    if (!parseInstructionBytes(bytesArray, testCase.instructionBytes, outError)) {
      outError = "case '" + testCase.name + "': " + outError;
      return false;
    }

    const auto* initialObject = caseObject->getObject("initial");
    if (initialObject) {
      if (!parseRegisterMap(initialObject->getObject("registers"),
                            testCase.initialRegisters, outError)) {
        outError = "case '" + testCase.name + "': " + outError;
        return false;
      }
      if (!parseFlagMap(initialObject->getObject("flags"),
                        testCase.initialFlags, outError)) {
        outError = "case '" + testCase.name + "': " + outError;
        return false;
      }
    }

    if (!parseRegisterMap(expectedObject->getObject("registers"),
                          testCase.expectedRegisters, outError)) {
      outError = "case '" + testCase.name + "': " + outError;
      return false;
    }
    if (!parseFlagMap(expectedObject->getObject("flags"), testCase.expectedFlags,
                      outError)) {
      outError = "case '" + testCase.name + "': " + outError;
      return false;
    }

    // Parse optional expected.branch_taken for branch assertion tests
    if (auto* bt = expectedObject->get("branch_taken")) {
      if (auto boolVal = bt->getAsBoolean()) {
        testCase.expectedBranchTaken = *boolVal;
      } else if (auto intVal = bt->getAsInteger()) {
        if (*intVal != 0 && *intVal != 1) {
          outError = "case '" + testCase.name + "': expected.branch_taken integer must be 0 or 1";
          return false;
        }
        testCase.expectedBranchTaken = (*intVal == 1);
      } else {
        outError = "case '" + testCase.name + "': expected.branch_taken must be bool or integer";
        return false;
      }
    }

    outCases.push_back(std::move(testCase));
  }

  return true;
}

} // namespace

int buildFullHandlerSeed(const std::string& outputPath,
                         const std::string& opcodePath,
                         uint64_t maxAttempts,
                         uint64_t randomSeed) {
  std::string parseError;
  HandlerMnemonicMap handlers = parseOpcodeHandlers(opcodePath, parseError);
  if (!parseError.empty()) {
    std::cerr << "Failed to parse handlers: " << parseError << std::endl;
    return 1;
  }

  std::unordered_set<std::string> discoveryTargets;
  for (const auto& [handler, mnemonics] : handlers) {
    if (kManualHandlerCases.contains(handler)) {
      continue;
    }

    for (const auto& mnemonic : mnemonics) {
      discoveryTargets.insert(normalizeMnemonic(mnemonic));
    }
  }

  MnemonicSampleMap samples =
      discoverMnemonicSamples(discoveryTargets, maxAttempts, randomSeed);

  std::vector<std::string> unresolvedHandlers;
  llvm::json::Array jsonCases;

  for (const auto& [handler, mnemonics] : handlers) {
    auto manualIt = kManualHandlerCases.find(handler);
    if (manualIt != kManualHandlerCases.end()) {
      const auto& spec = manualIt->second;
      auto smokeCase = buildSmokeCase(handler, spec.mnemonic, spec.instructionBytes,
                                      spec.initialRegisters, spec.initialFlags);
      jsonCases.push_back(toJsonCase(smokeCase, handler));
      continue;
    }

    std::optional<std::string> selectedMnemonic;
    std::vector<uint8_t> selectedBytes;

    for (const auto& mnemonic : mnemonics) {
      const std::string normalized = normalizeMnemonic(mnemonic);
      auto sampleIt = samples.find(normalized);
      if (sampleIt == samples.end()) {
        continue;
      }

      selectedMnemonic = normalized;
      selectedBytes = sampleIt->second;
      break;
    }

    if (!selectedMnemonic.has_value()) {
      unresolvedHandlers.push_back(handler);
      continue;
    }

    auto smokeCase = buildSmokeCase(handler, *selectedMnemonic, selectedBytes,
                                    kDefaultInitialRegisters, {});
    jsonCases.push_back(toJsonCase(smokeCase, handler));
  }

  if (!unresolvedHandlers.empty()) {
    std::cerr << "Unable to discover instruction bytes for handlers:";
    for (const auto& handler : unresolvedHandlers) {
      std::cerr << " " << handler;
    }
    std::cerr << std::endl;
    return 1;
  }

  llvm::json::Object root;
  root["schema"] = "mergen-oracle-seed-v1";
  root["generator"] = "rewrite_microtests --build-full-seed";
  root["opcode_path"] = opcodePath;
  root["max_attempts"] = static_cast<int64_t>(maxAttempts);
  root["random_seed"] = static_cast<int64_t>(randomSeed);
  root["cases"] = std::move(jsonCases);

  std::string serialized =
      llvm::formatv("{0:2}", llvm::json::Value(std::move(root))).str();
  serialized.push_back('\n');

  if (!writeTextFile(outputPath, serialized)) {
    std::cerr << "Failed to write full handler seed file: " << outputPath
              << std::endl;
    return 1;
  }

  std::cout << "Generated full handler seed: " << outputPath << std::endl;
  std::cout << "Handlers covered: " << handlers.size() << std::endl;
  return 0;
}

int testInit(const std::string& suiteFilter) {
  const char* vectorsEnv = std::getenv("MERGEN_TEST_VECTORS");
  const std::string vectorsPath =
      vectorsEnv ? vectorsEnv : "lifter/test/test_vectors/oracle_vectors.json";

  std::vector<InstructionTestCase> testCases;
  std::string loadError;
  if (!loadOracleCases(vectorsPath, testCases, loadError)) {
    std::cerr << "Failed to load oracle vectors: " << loadError << std::endl;
    return 1;
  }

  const char* checkFlagsEnv = std::getenv("MERGEN_TEST_CHECK_FLAGS");
  const bool checkFlags = checkFlagsEnv && std::string(checkFlagsEnv) == "1";
  if (!checkFlags) {
    std::cout << "Flag checks disabled (set MERGEN_TEST_CHECK_FLAGS=1 to enforce)"
              << std::endl;
  }

  InstructionTester tester;
  return tester.runAllTests(testCases, suiteFilter, checkFlags);
}

#else

int buildFullHandlerSeed(const std::string&, const std::string&, uint64_t,
                         uint64_t) {
  return 0;
}

int testInit(const std::string&) { return 0; }

#endif
