#pragma once

#include <cstdint>
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <map>
#include <string>
#include <vector>

// Structured diagnostics for the lifting pipeline.
// Each diagnostic has a reason code, severity, optional address, and message.
// After lifting, diagnostics can be emitted as JSON for tooling consumption.

enum class DiagSeverity : uint8_t {
  Info,    // Informational (e.g., outlining decisions, timing)
  Warning, // Non-fatal issue that may affect output quality
  Error,   // Failure that prevents correct lifting of a region
};

enum class DiagCode : uint16_t {
  // Instruction handling (1xx)
  InstructionNotImplemented = 100,
  InstructionUnsupported    = 101,

  // Control flow (2xx)
  UnresolvedIndirectJump    = 200,
  UnresolvedRetChain        = 201,
  MultiTargetSwitch         = 210,

  // Call handling (3xx)
  CallOutlinedImportThunk   = 300,
  CallOutlinedPdata         = 301,
  CallOutlinedUser          = 302,
  CallOutlinedSpecBailout   = 303,
  CallAbiApplied            = 310,
  CallIndirectUnresolved    = 311,

  // Memory / PE (4xx)
  PdataOutlineCount         = 400,
  ExportOutlineCount        = 401,
  MemoryReadFailed          = 410,

  // Pipeline (5xx)
  LiftComplete              = 500,
  OptimizationComplete      = 501,
  SignatureSearchComplete   = 502,
  LiftBlockBudgetExceeded   = 503,
  IncompleteBlockSealed     = 504,

  // Optimization fixpoint (51x)
  FixpointConverged         = 510,
  FixpointMaxIterations     = 511,

};

struct DiagnosticEntry {
  DiagCode    code;
  DiagSeverity severity;
  uint64_t    address;    // 0 if not applicable
  std::string message;
  std::string mnemonic;   // instruction mnemonic if applicable
};

struct LiftStats {
  unsigned blocks_attempted = 0;
  unsigned blocks_completed = 0;
  unsigned blocks_unreachable = 0;
  unsigned instructions_lifted = 0;
  unsigned instructions_unsupported = 0;
};

// Per-iteration record for the run_opts fixpoint loop.
// Counts are llvm::Module::getInstructionCount() after the named pass runs;
// `before` is the count at the top of the iteration (== `after_post` of the
// previous iteration, or `initial` for iter 0).
struct FixpointIteration {
  unsigned iteration;
  size_t before;
  size_t after_o1;
  size_t after_geploadpass;
  size_t after_replacetrunc;
  size_t after_promotestack;
  size_t after_promotemem;
  // Wall-clock time per pass (milliseconds). `ms` is the iteration total.
  double o1_ms;
  double geploadpass_ms;
  double replacetrunc_ms;
  double promotestack_ms;
  double promotemem_ms;
  double ms;
};

struct FixpointStats {
  unsigned iterations = 0;
  bool reached_cap = false;
  size_t initial_size = 0;       // module->getInstructionCount() before iter 0
  size_t final_loop_size = 0;    // count when the loop exits
  size_t final_o2_size = 0;      // count after the post-fixpoint O2 pipeline
  size_t final_post_size = 0;    // count after the post-passes (canonical naming etc.)
  std::vector<FixpointIteration> iteration_log;
};

class LiftDiagnostics {
  std::vector<DiagnosticEntry> entries;

public:
  void add(DiagCode code, DiagSeverity severity, uint64_t address,
           const std::string& message, const std::string& mnemonic = "") {
    entries.push_back({code, severity, address, message, mnemonic});
  }

  void info(DiagCode code, uint64_t address, const std::string& message) {
    add(code, DiagSeverity::Info, address, message);
  }

  void warning(DiagCode code, uint64_t address, const std::string& message,
               const std::string& mnemonic = "") {
    add(code, DiagSeverity::Warning, address, message, mnemonic);
  }

  void error(DiagCode code, uint64_t address, const std::string& message,
             const std::string& mnemonic = "") {
    add(code, DiagSeverity::Error, address, message, mnemonic);
  }

  const std::vector<DiagnosticEntry>& getEntries() const { return entries; }
  size_t size() const { return entries.size(); }
  bool empty() const { return entries.empty(); }
  bool hasErrors() const { return countBySeverity(DiagSeverity::Error) != 0; }

  size_t countBySeverity(DiagSeverity sev) const {
    size_t n = 0;
    for (const auto& e : entries)
      if (e.severity == sev) ++n;
    return n;
  }

  // Emit diagnostics + profile + stats as JSON string.
  std::string toJson(const std::vector<std::pair<std::string, double>>* profile = nullptr,
                     const struct LiftStats* stats = nullptr,
                     const struct FixpointStats* fixpoint = nullptr) const {
    std::ostringstream os;
    os << "{\n";

    // Diagnostics array.
    os << "  \"diagnostics\": [\n";
    for (size_t i = 0; i < entries.size(); ++i) {
      const auto& e = entries[i];
      os << "    {";
      os << "\"code\": " << static_cast<uint16_t>(e.code);
      os << ", \"severity\": \"" << severityStr(e.severity) << "\"";
      if (e.address != 0)
        os << ", \"address\": \"0x" << std::hex << e.address << std::dec << "\"";
      if (!e.mnemonic.empty())
        os << ", \"mnemonic\": \"" << escapeJson(e.mnemonic) << "\"";
      os << ", \"message\": \"" << escapeJson(e.message) << "\"";
      os << "}";
      if (i + 1 < entries.size()) os << ",";
      os << "\n";
    }
    os << "  ],\n";

    // Profile section.
    if (profile && !profile->empty()) {
      os << "  \"profile\": {\n";
      double total = 0;
      std::map<std::string, double> aggregatedProfile;
      for (const auto& [name, ms] : *profile) {
        aggregatedProfile[name] += ms;
        total += ms;
      }
      size_t emitted = 0;
      for (const auto& [name, ms] : aggregatedProfile) {
        os << "    \"" << escapeJson(name) << "\": " << std::fixed
           << std::setprecision(3) << ms;
        if (++emitted < aggregatedProfile.size()) os << ",";
        os << "\n";
      }
      os << "  },\n";
      os << "  \"total_ms\": " << std::fixed << std::setprecision(3) << total << ",\n";
    }

    // Lift stats.
    if (stats) {
      os << "  \"lift_stats\": {\n";
      os << "    \"blocks_attempted\": " << stats->blocks_attempted << ",\n";
      os << "    \"blocks_completed\": " << stats->blocks_completed << ",\n";
      os << "    \"blocks_unreachable\": " << stats->blocks_unreachable << ",\n";
      os << "    \"instructions_lifted\": " << stats->instructions_lifted << ",\n";
      os << "    \"instructions_unsupported\": " << stats->instructions_unsupported << "\n";
      os << "  },\n";
    }
    // Optimization fixpoint stats.
    if (fixpoint) {
      os << "  \"optimization\": {\n";
      os << "    \"iterations\": " << fixpoint->iterations << ",\n";
      os << "    \"reached_cap\": " << (fixpoint->reached_cap ? "true" : "false") << ",\n";
      os << "    \"initial_size\": " << fixpoint->initial_size << ",\n";
      os << "    \"final_loop_size\": " << fixpoint->final_loop_size << ",\n";
      os << "    \"final_o2_size\": " << fixpoint->final_o2_size << ",\n";
      os << "    \"final_post_size\": " << fixpoint->final_post_size << ",\n";
      os << "    \"iteration_log\": [";
      for (size_t i = 0; i < fixpoint->iteration_log.size(); ++i) {
        const auto& it = fixpoint->iteration_log[i];
        if (i == 0) os << "\n";
        os << "      {";
        os << "\"iter\": " << it.iteration;
        os << ", \"before\": " << it.before;
        os << ", \"after_o1\": " << it.after_o1;
        os << ", \"after_geploadpass\": " << it.after_geploadpass;
        os << ", \"after_replacetrunc\": " << it.after_replacetrunc;
        os << ", \"after_promotestack\": " << it.after_promotestack;
        os << ", \"after_promotemem\": " << it.after_promotemem;
        os << std::fixed << std::setprecision(3);
        os << ", \"o1_ms\": " << it.o1_ms;
        os << ", \"geploadpass_ms\": " << it.geploadpass_ms;
        os << ", \"replacetrunc_ms\": " << it.replacetrunc_ms;
        os << ", \"promotestack_ms\": " << it.promotestack_ms;
        os << ", \"promotemem_ms\": " << it.promotemem_ms;
        os << ", \"ms\": " << it.ms;
        os << "}";
        if (i + 1 < fixpoint->iteration_log.size()) os << ",";
        os << "\n";
      }
      os << "    ]\n";
      os << "  },\n";
    }


    // Summary.
    os << "  \"summary\": {";
    os << "\"total\": " << entries.size();
    os << ", \"info\": " << countBySeverity(DiagSeverity::Info);
    os << ", \"warning\": " << countBySeverity(DiagSeverity::Warning);
    os << ", \"error\": " << countBySeverity(DiagSeverity::Error);
    os << "}\n";
    os << "}\n";
    return os.str();
  }

  // Print human-readable summary to stderr.
  void printSummary() const {
    size_t warnings = countBySeverity(DiagSeverity::Warning);
    size_t errors = countBySeverity(DiagSeverity::Error);
    if (errors > 0)
      std::cerr << "[diagnostics] " << errors << " error(s), "
                << warnings << " warning(s)\n";
    else if (warnings > 0)
      std::cerr << "[diagnostics] " << warnings << " warning(s)\n";
  }

private:
  static const char* severityStr(DiagSeverity s) {
    switch (s) {
    case DiagSeverity::Info: return "info";
    case DiagSeverity::Warning: return "warning";
    case DiagSeverity::Error: return "error";
    }
    return "unknown";
  }

  static std::string escapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
      if (c == '"')       out += "\\\"";
      else if (c == '\\') out += "\\\\";
      else if (c == '\n') out += "\\n";
      else if (c == '\r') out += "\\r";
      else if (c == '\t') out += "\\t";
      else if (c < 0x20) {
        // Escape all other control characters as \uXXXX.
        char buf[8];
        snprintf(buf, sizeof(buf), "\\u%04x", c);
        out += buf;
      } else {
        out += static_cast<char>(c);
      }
    }
    return out;
  }
};

// Scoped timer for pipeline profiling. Records elapsed wall-clock time
// for each named stage into a vector of (name, milliseconds) pairs.
class PipelineProfiler {
  using clock = std::chrono::high_resolution_clock;
  using time_point = std::chrono::time_point<clock>;

  std::vector<std::pair<std::string, double>> stages;
  std::string currentStage;
  time_point stageStart;
  bool running = false;

public:
  class ScopedSample {
    PipelineProfiler* profiler;
    std::string name;
    time_point start;

  public:
    ScopedSample(PipelineProfiler& profilerRef, const std::string& sampleName)
        : profiler(&profilerRef), name(sampleName), start(clock::now()) {}

    ScopedSample(const ScopedSample&) = delete;
    ScopedSample& operator=(const ScopedSample&) = delete;

    ScopedSample(ScopedSample&& other) noexcept
        : profiler(other.profiler), name(std::move(other.name)),
          start(other.start) {
      other.profiler = nullptr;
    }

    ScopedSample& operator=(ScopedSample&& other) noexcept {
      if (this == &other)
        return *this;
      if (profiler) {
        profiler->addSample(
            name, std::chrono::duration<double, std::milli>(clock::now() - start).count());
      }
      profiler = other.profiler;
      name = std::move(other.name);
      start = other.start;
      other.profiler = nullptr;
      return *this;
    }

    ~ScopedSample() {
      if (!profiler)
        return;
      profiler->addSample(
          name, std::chrono::duration<double, std::milli>(clock::now() - start).count());
    }
  };

  void begin(const std::string& name) {
    end(); // close previous stage if any
    currentStage = name;
    stageStart = clock::now();
    running = true;
  }

  void end() {
    if (!running) return;
    auto elapsed = std::chrono::duration<double, std::milli>(
        clock::now() - stageStart).count();
    stages.push_back({currentStage, elapsed});
    running = false;
  }

  void addSample(const std::string& name, double elapsedMilliseconds) {
    stages.push_back({name, elapsedMilliseconds});
  }

  ScopedSample sample(const std::string& name) {
    return ScopedSample(*this, name);
  }

  const std::vector<std::pair<std::string, double>>& getStages() const {
    return stages;
  }
};
