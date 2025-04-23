
// #include "lifterClass.hpp"
// #include "tester.hpp"
// #include <Zydis/Decoder.h>
// #include <Zydis/DecoderTypes.h>
// #include <Zydis/Disassembler.h>
// #include <Zydis/Register.h>
// #include <fstream>
// #include <llvm/IR/Constants.h>

// // & all the tests, if test fail, it should return 0

// // make this so tests can be added seperately

// bool test1(Tester* tester) {

//   std::vector<uint8_t> bytes = {0x48, 0x01, 0xc8};
//   tester->setRegister(ZYDIS_REGISTER_RAX, 5);
//   tester->setRegister(ZYDIS_REGISTER_RCX, 5);
//   tester->disassembleBytesAndLift(bytes);

//   auto res1 = tester->isRegisterEqualTo(ZYDIS_REGISTER_RAX, 10);
//   return res1;
// }

// bool test2(Tester* tester) {

//   std::vector<uint8_t> bytes = {0x48, 0x01, 0xc8};
//   tester->setRegister(ZYDIS_REGISTER_RAX, 10);
//   tester->setRegister(ZYDIS_REGISTER_RCX, 10);
//   tester->disassembleBytesAndLift(bytes);

//   auto res1 = tester->isRegisterEqualTo(ZYDIS_REGISTER_RAX, 20);
//   return res1;
// }

// struct ParsedSide {
//   std::vector<std::tuple<std::string, uint64_t, int>> registers;
//   std::optional<std::pair<uint64_t, int>> flags;
// };

// struct InstructionHeader {
//   std::vector<uint8_t> instruction_bytes;
//   std::string mnemonic;
//   std::string operand_size;
// };

// std::string trim(const std::string& s) {
//   size_t start = s.find_first_not_of(" \t");
//   size_t end = s.find_last_not_of(" \t");
//   if (start == std::string::npos)
//     return "";
//   return s.substr(start, end - start + 1);
// }

// uint64_t swap_endianness(uint64_t value, int num_bytes) {
//   uint64_t result = 0;
//   for (int i = 0; i < num_bytes; ++i) {
//     int shift = 8 * (num_bytes - 1 - i);
//     uint8_t byte = (value >> shift) & 0xFF;
//     result |= static_cast<uint64_t>(byte) << (8 * i);
//   }
//   return result;
// }

// ParsedSide parse_side(const std::string& side_str) {
//   ParsedSide result;

//   std::string s = side_str;

//   // Remove leading "in:" or "out:"
//   size_t colon_pos = s.find(':');
//   if (colon_pos != std::string::npos) {
//     std::string prefix = s.substr(0, colon_pos);
//     if (prefix == "in" || prefix == "out") {
//       s = s.substr(colon_pos + 1);
//     }
//   }

//   std::vector<std::string> tokens;
//   size_t start = 0;
//   while (true) {
//     size_t comma_pos = s.find(',', start);
//     if (comma_pos == std::string::npos) {
//       tokens.push_back(trim(s.substr(start)));
//       break;
//     }
//     tokens.push_back(trim(s.substr(start, comma_pos - start)));
//     start = comma_pos + 1;
//   }

//   for (const auto& token : tokens) {
//     if (token.empty())
//       continue;

//     if (token.substr(0, 6) == "flags:") {
//       std::string value_str = token.substr(6);
//       value_str = trim(value_str);
//       if (value_str.empty())
//         continue;
//       if (value_str[0] == '#') {
//         value_str = value_str.substr(1);
//       }
//       int num_bytes = value_str.length() / 2;
//       uint64_t value = 0;
//       try {
//         value = std::stoull(value_str, nullptr, 16);
//       } catch (...) {
//         // invalid value, treat as 0
//       }
//       result.flags = std::make_pair(value, num_bytes);
//     } else {
//       size_t colon_pos = token.find(':');
//       if (colon_pos == std::string::npos)
//         continue;
//       std::string reg_part = trim(token.substr(0, colon_pos));
//       std::string value_part = trim(token.substr(colon_pos + 1));
//       if (value_part.empty())
//         continue;
//       if (value_part[0] == '#') {
//         value_part = value_part.substr(1);
//       }
//       int num_bytes = value_part.length() / 2;
//       uint64_t value = 0;
//       try {
//         value = std::stoull(value_part, nullptr, 16);
//       } catch (...) {
//         // invalid value, treat as 0
//       }
//       result.registers.emplace_back(reg_part, value, num_bytes);
//     }
//   }

//   return result;
// }

// std::pair<ParsedSide, ParsedSide> parse_test_line(const std::string& line) {
//   size_t pipe_pos = line.find('|');
//   if (pipe_pos == std::string::npos) {
//     return {ParsedSide(), ParsedSide()};
//   }

//   std::string in_str = line.substr(0, pipe_pos);
//   std::string out_str = line.substr(pipe_pos + 1);

//   ParsedSide in_side = parse_side(in_str);
//   ParsedSide out_side = parse_side(out_str);

//   return {in_side, out_side};
// }

// InstructionHeader parse_instruction_header(const std::string& line) {
//   InstructionHeader header;
//   std::vector<std::string> parts;
//   size_t start = 0;
//   while (true) {
//     size_t semicolon_pos = line.find(';', start);
//     if (semicolon_pos == std::string::npos) {
//       parts.push_back(trim(line.substr(start)));
//       break;
//     }
//     parts.push_back(trim(line.substr(start, semicolon_pos - start)));
//     start = semicolon_pos + 1;
//   }

//   if (parts.size() < 4) {
//     return header;
//   }

//   std::string bytes_str = parts[1];
//   if (bytes_str.empty() || bytes_str[0] != '#') {
//     return header;
//   }
//   bytes_str = bytes_str.substr(1);
//   for (size_t i = 0; i < bytes_str.size(); i += 2) {
//     std::string byte_str = bytes_str.substr(i, 2);
//     try {
//       uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
//       header.instruction_bytes.push_back(byte);
//     } catch (...) {
//       // invalid byte, skip
//     }
//   }

//   header.mnemonic = parts[2];
//   header.operand_size = parts[3];

//   return header;
// }

// ZydisRegister register_name_to_enum(const std::string& reg_name) {
//   static const std::unordered_map<std::string, ZydisRegister> register_map =
//   {
//       {"rax", ZYDIS_REGISTER_RAX},   {"eax", ZYDIS_REGISTER_EAX},
//       {"ax", ZYDIS_REGISTER_AX},     {"al", ZYDIS_REGISTER_AL},
//       {"rcx", ZYDIS_REGISTER_RCX},   {"ecx", ZYDIS_REGISTER_ECX},
//       {"cx", ZYDIS_REGISTER_CX},     {"cl", ZYDIS_REGISTER_CL},
//       {"rdx", ZYDIS_REGISTER_RDX},   {"edx", ZYDIS_REGISTER_EDX},
//       {"dx", ZYDIS_REGISTER_DX},     {"dl", ZYDIS_REGISTER_DL},
//       {"rbx", ZYDIS_REGISTER_RBX},   {"ebx", ZYDIS_REGISTER_EBX},
//       {"bx", ZYDIS_REGISTER_BX},     {"bl", ZYDIS_REGISTER_BL},
//       {"rsp", ZYDIS_REGISTER_RSP},   {"esp", ZYDIS_REGISTER_ESP},
//       {"sp", ZYDIS_REGISTER_SP},     {"spl", ZYDIS_REGISTER_SPL},
//       {"rbp", ZYDIS_REGISTER_RBP},   {"ebp", ZYDIS_REGISTER_EBP},
//       {"bp", ZYDIS_REGISTER_BP},     {"bpl", ZYDIS_REGISTER_BPL},
//       {"rsi", ZYDIS_REGISTER_RSI},   {"esi", ZYDIS_REGISTER_ESI},
//       {"si", ZYDIS_REGISTER_SI},     {"sil", ZYDIS_REGISTER_SIL},
//       {"rdi", ZYDIS_REGISTER_RDI},   {"edi", ZYDIS_REGISTER_EDI},
//       {"di", ZYDIS_REGISTER_DI},     {"dil", ZYDIS_REGISTER_DIL},
//       {"r8", ZYDIS_REGISTER_R8},     {"r8d", ZYDIS_REGISTER_R8D},
//       {"r8w", ZYDIS_REGISTER_R8W},   {"r8b", ZYDIS_REGISTER_R8B},
//       {"r9", ZYDIS_REGISTER_R9},     {"r9d", ZYDIS_REGISTER_R9D},
//       {"r9w", ZYDIS_REGISTER_R9W},   {"r9b", ZYDIS_REGISTER_R9B},
//       {"r10", ZYDIS_REGISTER_R10},   {"r10d", ZYDIS_REGISTER_R10D},
//       {"r10w", ZYDIS_REGISTER_R10W}, {"r10b", ZYDIS_REGISTER_R10B},
//       {"r11", ZYDIS_REGISTER_R11},   {"r11d", ZYDIS_REGISTER_R11D},
//       {"r11w", ZYDIS_REGISTER_R11W}, {"r11b", ZYDIS_REGISTER_R11B},
//       {"r12", ZYDIS_REGISTER_R12},   {"r12d", ZYDIS_REGISTER_R12D},
//       {"r12w", ZYDIS_REGISTER_R12W}, {"r12b", ZYDIS_REGISTER_R12B},
//       {"r13", ZYDIS_REGISTER_R13},   {"r13d", ZYDIS_REGISTER_R13D},
//       {"r13w", ZYDIS_REGISTER_R13W}, {"r13b", ZYDIS_REGISTER_R13B},
//       {"r14", ZYDIS_REGISTER_R14},   {"r14d", ZYDIS_REGISTER_R14D},
//       {"r14w", ZYDIS_REGISTER_R14W}, {"r14b", ZYDIS_REGISTER_R14B},
//       {"r15", ZYDIS_REGISTER_R15},   {"r15d", ZYDIS_REGISTER_R15D},
//       {"r15w", ZYDIS_REGISTER_R15W}, {"r15b", ZYDIS_REGISTER_R15B},
//   };

//   auto it = register_map.find(reg_name);
//   if (it != register_map.end()) {
//     return it->second;
//   }
//   return ZYDIS_REGISTER_NONE;
// }

// void process_block(const std::vector<std::string>& block,
//                    std::vector<TestCase>& test_cases) {
//   if (block.empty())
//     return;
//   InstructionHeader header = parse_instruction_header(block[0]);
//   if (header.instruction_bytes.empty())
//     return;

//   static int test_case_counter = 1;

//   for (size_t i = 1; i < block.size(); ++i) {
//     const std::string& line = block[i];
//     auto [in_side, out_side] = parse_test_line(line);

//     TestCase tc;
//     tc.name = header.mnemonic + "_test" +
//     std::to_string(test_case_counter++); std::replace(tc.name.begin(),
//     tc.name.end(), ' ', '_'); std::replace(tc.name.begin(), tc.name.end(),
//     ',', '_'); tc.instruction_bytes = header.instruction_bytes;
//     tc.couldBeUndefined = true;

//     // Process initial registers
//     for (const auto& reg_tuple : in_side.registers) {
//       std::string reg_name;
//       uint64_t value;
//       int num_bytes;
//       std::tie(reg_name, value, num_bytes) = reg_tuple;
//       ZydisRegister reg = register_name_to_enum(reg_name);
//       if (reg == ZYDIS_REGISTER_NONE)
//         continue;
//       uint64_t swapped_value = swap_endianness(value, num_bytes);
//       tc.initial_registers.emplace_back(reg, swapped_value);
//     }

//     // Process initial flags
//     if (in_side.flags) {
//       auto [value, num_bytes] = in_side.flags.value();
//       uint64_t swapped_value = swap_endianness(value, num_bytes);
//       tc.initial_flags = parseFlagStates(swapped_value);
//     }

//     // Process expected registers
//     for (const auto& reg_tuple : out_side.registers) {
//       std::string reg_name;
//       uint64_t value;
//       int num_bytes;
//       std::tie(reg_name, value, num_bytes) = reg_tuple;
//       ZydisRegister reg = register_name_to_enum(reg_name);
//       if (reg == ZYDIS_REGISTER_NONE)
//         continue;
//       uint64_t swapped_value = swap_endianness(value, num_bytes);
//       tc.expected_registers.emplace_back(reg, swapped_value);
//     }

//     // Process expected flags
//     if (out_side.flags) {
//       auto [value, num_bytes] = out_side.flags.value();
//       uint64_t swapped_value = swap_endianness(value, num_bytes);
//       tc.expected_flags = parseFlagStates(swapped_value);
//     }

//     test_cases.push_back(tc);
//   }
// }
// std::vector<TestCase> parse_test_cases(const std::string& filename) {
//   std::vector<TestCase> test_cases;
//   std::ifstream file(filename.c_str(), std::ios::binary);
//   if (!file.is_open()) {
//     return test_cases;
//   }

//   std::vector<std::string> current_block;
//   std::string line;
//   while (std::getline(file, line)) {
//     line = trim(line);
//     if (line.empty())
//       continue;

//     if (line.find("instr:") == 0) {
//       if (!current_block.empty()) {
//         process_block(current_block, test_cases);
//         current_block.clear();
//       }
//       current_block.push_back(line);
//     } else {
//       if (!current_block.empty()) {
//         current_block.push_back(line);
//       }
//     }
//   }

//   if (!current_block.empty()) {
//     process_block(current_block, test_cases);
//   }

//   return test_cases;
// }

// int testInit(std::string file) {
//   llvm::LLVMContext context;
//   std::string mod_name = "my_lifting_module";
//   llvm::Module lifting_module = llvm::Module(mod_name.c_str(), context);

//   std::vector<llvm::Type*> argTypes;
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::Type::getInt64Ty(context));
//   argTypes.push_back(llvm::PointerType::get(context, 0));
//   argTypes.push_back(llvm::PointerType::get(context, 0)); // temp fix TEB

//   auto functionType =
//       llvm::FunctionType::get(llvm::Type::getInt64Ty(context), argTypes, 0);

//   const std::string function_name = "main";
//   auto function =
//       llvm::Function::Create(functionType, llvm::Function::ExternalLinkage,
//                              function_name.c_str(), lifting_module);
//   const std::string block_name = "entry";
//   auto bb = llvm::BasicBlock::Create(context, block_name.c_str(), function);

//   llvm::InstSimplifyFolder Folder(lifting_module.getDataLayout());
//   llvm::IRBuilder<llvm::InstSimplifyFolder> builder =
//       llvm::IRBuilder<llvm::InstSimplifyFolder>(bb, Folder);

//   lifterClass<>* main = new lifterClass(builder, 0x133700);

//   // we will need a resetter, though im not sure if we need to only reset
//   // registers, flags and mem or llvm context?

//   auto tester = Tester(main, true);
//   tester.addTest(test1, "test");
//   tester.addTest(test2, "test2");
//   TestCase tc = {.name = "testcase",
//                  .instruction_bytes = {0x90},
//                  .initial_registers = {{ZYDIS_REGISTER_RAX, 1}},
//                  .initial_flags = {{FLAG_CF, FlagState::SET}},

//                  .expected_registers = {{ZYDIS_REGISTER_RAX, 1}},
//                  .expected_flags = {{FLAG_CF, FlagState::SET}},
//                  .couldBeUndefined = false};

//   /*
//   auto expectedFlags = tester.parseFlagStates(0b101);
//   for (auto [a, b] : expectedFlags) {
//     outs() << "a: " << a << " b:" << b << "\n";
//   }
//   */
//   TestCase tc2 = {.name = "testcase2",
//                   .instruction_bytes = {0x90},
//                   .initial_flags = parseFlagStates(4),

//                   .expected_flags = parseFlagStates(4),
//                   .couldBeUndefined = true};

//   TestCase tccmov = {.name = "testcasecmov",
//                      .instruction_bytes = {0x48, 0x0F, 0x44, 0xC1},
//                      .initial_registers = {{ZYDIS_REGISTER_RAX, 1},
//                                            {ZYDIS_REGISTER_RCX, 1337}},
//                      .initial_flags = {{FLAG_ZF, FlagState::SET}},

//                      .expected_registers = {{ZYDIS_REGISTER_RAX, 1337}},
//                      .couldBeUndefined = true};

//   TestCase tccmov2 = {.name = "testcasecmov23",
//                       .instruction_bytes = {0x48, 0x0F, 0x44, 0xC1},
//                       .initial_registers = {{ZYDIS_REGISTER_RAX, 1337},
//                                             {ZYDIS_REGISTER_RCX, 1}},
//                       .initial_flags = {{FLAG_ZF, FlagState::CLEAR}},

//                       .expected_registers = {{ZYDIS_REGISTER_RAX, 1337}},
//                       .couldBeUndefined = true};

//   tester.addTest(tc);
//   tester.addTest(tc2);
//   tester.addTest(tccmov);
//   tester.addTest(tccmov2);
//   auto a = parse_test_cases(file);
//   for (auto x : a) {
//     tester.addTest(x);
//   }
//   return tester.runAllTests();
// }
