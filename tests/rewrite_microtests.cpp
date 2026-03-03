#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>
#ifdef _WIN32
#include <process.h>
#endif

namespace fs = std::filesystem;

struct Sample {
  std::string name;
  std::string symbol;
  std::string asmSource;
  std::vector<std::string> patterns;
};


static std::string readEnvOrEmpty(const char *key) {
#ifdef _WIN32
  char *raw = nullptr;
  size_t len = 0;
  if (_dupenv_s(&raw, &len, key) != 0 || raw == nullptr) {
    return {};
  }
  std::string value(raw);
  free(raw);
  return value;
#else
  const char *raw = std::getenv(key);
  return raw != nullptr ? raw : "";
#endif
}

static std::string formatCommand(const std::string &executable,
                                 const std::vector<std::string> &args) {
  std::string command = executable;
  for (const auto &arg : args) {
    if (arg.find(' ') != std::string::npos) {
      command += " \"" + arg + "\"";
    } else {
      command += " " + arg;
    }
  }
  return command;
}

static int runProcess(const std::string &executable,
                      const std::vector<std::string> &args) {
  std::cout << formatCommand(executable, args) << std::endl;
#ifdef _WIN32
  std::vector<const char *> argv;
  argv.reserve(args.size() + 2);
  std::string argv0 = fs::path(executable).filename().string();
  if (argv0.empty()) {
    argv0 = executable;
  }
  argv.push_back(argv0.c_str());
  for (const auto &arg : args) {
    argv.push_back(arg.c_str());
  }
  argv.push_back(nullptr);
  const bool hasPathSeparator = executable.find('\\') != std::string::npos ||
                                executable.find('/') != std::string::npos;
  if (hasPathSeparator) {
    return _spawnv(_P_WAIT, executable.c_str(), argv.data());
  }
  return _spawnvp(_P_WAIT, executable.c_str(), argv.data());
#else
  return std::system(formatCommand(executable, args).c_str());
#endif
}

static std::string readFile(const fs::path &path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs.is_open()) {
    throw std::runtime_error("Failed to open file: " + path.string());
  }
  std::ostringstream oss;
  oss << ifs.rdbuf();
  return oss.str();
}

static std::string parseSymbolAddressFromMap(const fs::path &mapPath,
                                             const std::string &symbol) {
  std::ifstream mapFile(mapPath);
  if (!mapFile.is_open()) {
    throw std::runtime_error("Map file not found: " + mapPath.string());
  }

  const std::regex symbolRegex("\\s" + symbol + "\\s");
  std::string line;
  while (std::getline(mapFile, line)) {
    if (!std::regex_search(line, symbolRegex)) {
      continue;
    }

    std::istringstream iss(line);
    std::vector<std::string> tokens;
    std::string token;
    while (iss >> token) {
      tokens.push_back(token);
    }

    if (tokens.size() >= 3) {
      return "0x" + tokens[2];
    }
  }

  throw std::runtime_error("Symbol " + symbol + " not found in map file: " +
                           mapPath.string());
}

int main(int argc, char *argv[]) {
  try {
    const fs::path repoRoot = fs::current_path();

    fs::path workDir = repoRoot.parent_path() / "rewrite-microtests-work";
    if (argc >= 2) {
      workDir = fs::path(argv[1]);
    }

    fs::path lifterPath = repoRoot / "build_iced" / "lifter.exe";
    if (argc >= 3) {
      lifterPath = fs::path(argv[2]);
    }

    if (!fs::exists(lifterPath)) {
      throw std::runtime_error("Lifter not found at: " + lifterPath.string());
    }

    std::string nasmExe = readEnvOrEmpty("NASM_EXE");
    if (nasmExe.empty()) {
      nasmExe = "nasm";
    }
    std::string linkerExe = readEnvOrEmpty("LINK_EXE");
    if (linkerExe.empty()) {
      linkerExe = "link.exe";
    }

    const std::vector<Sample> samples = {
        {"branch", "branch_target",
         R"ASM(default rel
bits 64

global start
global branch_target
extern ExitProcess

section .text
branch_target:
    push rbp
    mov rbp, rsp
    mov eax, ecx
    cmp eax, 5
    jg .gt
    add eax, 100
    jmp .done
.gt:
    imul eax, eax, 3
.done:
    xor eax, 0x33
    pop rbp
    ret

start:
    sub rsp, 40
    mov ecx, 10
    call branch_target
    mov ecx, eax
    call ExitProcess
)ASM",
         {"select i1", "mul i32 %0, 3", "add i32 %0, 100", "xor i32"}},
        {"stack", "stack_target",
         R"ASM(default rel
bits 64

global start
global stack_target
extern ExitProcess

section .text
stack_target:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov dword [rsp + 16], 0x11111111
    mov eax, dword [rsp + 16]
    add eax, 0x22222222
    rol eax, 1
    add rsp, 32
    pop rbp
    ret

start:
    sub rsp, 40
    call stack_target
    mov ecx, eax
    call ExitProcess
)ASM",
         {"ret i64 1717986918"}},
        {"indirect", "jump_target",
         R"ASM(default rel
bits 64

global start
global jump_target
extern ExitProcess

section .text
jump_target:
    push rbp
    mov rbp, rsp

    mov ecx, 2
    lea rax, [rel jump_table]
    movsxd rdx, dword [rax + rcx * 4]
    add rax, rdx
    jmp rax

case0:
    mov eax, 0x10
    jmp done_label
case1:
    mov eax, 0x20
    jmp done_label
case2:
    mov eax, 0x30
done_label:
    add eax, 5
    pop rbp
    ret

jump_table:
    dd case0 - jump_table
    dd case1 - jump_table
    dd case2 - jump_table

start:
    sub rsp, 40
    call jump_target
    mov ecx, eax
    call ExitProcess
)ASM",
         {"ret i64 53"}},
        {"instr_add", "instr_add_target",
         R"ASM(default rel
bits 64

global start
global instr_add_target
extern ExitProcess

section .text
instr_add_target:
    push rbp
    mov rbp, rsp
    mov eax, 7
    add eax, 5
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_add_target
    mov ecx, eax
    call ExitProcess
)ASM",
         {"ret i64 12"}},
        {"instr_sub", "instr_sub_target",
         R"ASM(default rel
bits 64

global start
global instr_sub_target
extern ExitProcess

section .text
instr_sub_target:
    push rbp
    mov rbp, rsp
    mov eax, 100
    sub eax, 58
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_sub_target
    mov ecx, eax
    call ExitProcess
)ASM",
         {"ret i64 42"}},
        {"instr_xor", "instr_xor_target",
         R"ASM(default rel
bits 64

global start
global instr_xor_target
extern ExitProcess

section .text
instr_xor_target:
    push rbp
    mov rbp, rsp
    mov eax, 0x55
    xor eax, 0x0f
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_xor_target
    mov ecx, eax
    call ExitProcess
)ASM",
         {"ret i64 90"}},
        {"instr_rol", "instr_rol_target",
         R"ASM(default rel
bits 64

global start
global instr_rol_target
extern ExitProcess

section .text
instr_rol_target:
    push rbp
    mov rbp, rsp
    mov eax, 0x11
    rol eax, 1
    pop rbp
    ret

start:
    sub rsp, 40
    call instr_rol_target
    mov ecx, eax
    call ExitProcess
)ASM",
         {"ret i64 34"}},
    };

    fs::create_directories(workDir);
    const fs::path irDir = workDir / "ir_outputs";
    fs::create_directories(irDir);

    bool failed = false;

    for (const auto &sample : samples) {
      const fs::path asmPath = workDir / (sample.name + ".asm");
      const fs::path objPath = workDir / (sample.name + ".obj");
      const fs::path exePath = workDir / (sample.name + ".exe");
      const fs::path mapPath = workDir / (sample.name + ".map");

      {
        std::ofstream ofs(asmPath, std::ios::binary);
        if (!ofs.is_open()) {
          throw std::runtime_error("Failed to write asm file: " + asmPath.string());
        }
        ofs << sample.asmSource;
      }

      if (runProcess(nasmExe, {"-f", "win64", "-gcv8", "-o", objPath.string(),
                              asmPath.string()}) != 0) {
        throw std::runtime_error("NASM failed for sample: " + sample.name);
      }

      if (runProcess(linkerExe,
                     {"/nologo", "/entry:start", "/subsystem:console",
                      "/out:" + exePath.string(), "/map:" + mapPath.string(),
                      objPath.string(), "kernel32.lib"}) != 0) {
        throw std::runtime_error("Linker failed for sample: " + sample.name);
      }

      const std::string targetAddress = parseSymbolAddressFromMap(mapPath, sample.symbol);

      std::cout << "Lifting " << exePath << " @ " << targetAddress << std::endl;
      if (runProcess(lifterPath.string(), {exePath.string(), targetAddress}) != 0) {
        throw std::runtime_error("lifter.exe failed for sample: " + sample.name);
      }

      const fs::path outputLl = repoRoot / "output.ll";
      const fs::path outputNoOptsLl = repoRoot / "output_no_opts.ll";
      fs::copy_file(outputLl, irDir / (sample.name + ".ll"),
                    fs::copy_options::overwrite_existing);
      fs::copy_file(outputNoOptsLl, irDir / (sample.name + "_no_opts.ll"),
                    fs::copy_options::overwrite_existing);

      const std::string optimizedIr = readFile(irDir / (sample.name + ".ll"));
      for (const auto &pattern : sample.patterns) {
        if (optimizedIr.find(pattern) != std::string::npos) {
          std::cout << "PASS: " << sample.name << " contains '" << pattern
                    << "'" << std::endl;
        } else {
          std::cout << "FAIL: " << sample.name << " missing '" << pattern
                    << "'" << std::endl;
          failed = true;
        }
      }
    }

    if (failed) {
      std::cout << "One or more microtests failed." << std::endl;
      return 1;
    }

    std::cout << "All embedded microtests passed. IR files: " << irDir << std::endl;
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "ERROR: " << ex.what() << std::endl;
    return 1;
  }
}
