#pragma once
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif // _CRT_SECURE_NO_WARNINGS
#define _SILENCE_ALL_CXX20_DEPRECATION_WARNINGS
#define _SILENCE_ALL_CXX23_DEPRECATION_WARNINGS
#ifndef ZYDIS_STATIC_BUILD
#define ZYDIS_STATIC_BUILD
#endif // ZYDIS_STATIC_BUILD
#ifndef NDEBUG
#define NDEBUG
#endif

// #define _NODEV

#ifndef _NODEV
#define printvalue(x)                                                          \
  do {                                                                         \
    debugging::printLLVMValue(x, #x);                                          \
  } while (0);
// outs() << " " #x " : "; x->print(outs()); outs() << "\n";  outs().flush();
#define printvalue2(x)                                                         \
  do {                                                                         \
    debugging::printValue(x, #x);                                              \
  } while (0);
#else
#define printvalue(x) ((void)0);
#define printvalue2(x) ((void)0);
#endif // _NODEV

#define printvalueforce(x)                                                     \
  do {                                                                         \
    outs() << " " #x " : ";                                                    \
    x->print(outs());                                                          \
    outs() << "\n";                                                            \
    outs().flush();                                                            \
  } while (0);

#define printvalueforce2(x)                                                    \
  do {                                                                         \
    outs() << " " #x " : " << x << "\n";                                       \
    outs().flush();                                                            \
  } while (0);

#pragma warning(disable : 4996)
#pragma warning(disable : 4146)
#include <any>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <tuple>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX
#else
#endif // _WIN32

#include "utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include <Zydis/Zydis.h>

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/InstructionSimplify.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/MemoryDependenceAnalysis.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/MemorySSAUpdater.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PatternMatch.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/KnownBits.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Transforms/IPO/ConstantMerge.h"
#include "llvm/Transforms/IPO/CrossDSOCFI.h"
#include "llvm/Transforms/IPO/SCCP.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/ADCE.h"
#include "llvm/Transforms/Scalar/DCE.h"
#include "llvm/Transforms/Scalar/DeadStoreElimination.h"
#include "llvm/Transforms/Scalar/EarlyCSE.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/Transforms/Scalar/MergedLoadStoreMotion.h"
#include "llvm/Transforms/Scalar/NewGVN.h"
#include "llvm/Transforms/Scalar/Reassociate.h"
#include "llvm/Transforms/Scalar/Reg2Mem.h"
#include "llvm/Transforms/Scalar/SCCP.h"
#include "llvm/Transforms/Scalar/SROA.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/BasicAliasAnalysis.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/InlineAdvisor.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/Analysis/ScopedNoAliasAA.h"
#include "llvm/Analysis/TypeBasedAliasAnalysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/PGOOptions.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/AggressiveInstCombine/AggressiveInstCombine.h"
#include "llvm/Transforms/Coroutines/CoroCleanup.h"
#include "llvm/Transforms/Coroutines/CoroConditionalWrapper.h"
#include "llvm/Transforms/Coroutines/CoroEarly.h"
#include "llvm/Transforms/Coroutines/CoroElide.h"
#include "llvm/Transforms/Coroutines/CoroSplit.h"
#include "llvm/Transforms/IPO/AlwaysInliner.h"
#include "llvm/Transforms/IPO/Annotation2Metadata.h"
#include "llvm/Transforms/IPO/ArgumentPromotion.h"
#include "llvm/Transforms/IPO/CalledValuePropagation.h"
#include "llvm/Transforms/IPO/ConstantMerge.h"
#include "llvm/Transforms/IPO/CrossDSOCFI.h"
#include "llvm/Transforms/IPO/DeadArgumentElimination.h"
#include "llvm/Transforms/IPO/ElimAvailExtern.h"

// #include "llvm/Transforms/IPO/EmbedBitcodePass.h"
#include "llvm/Transforms/IPO/ForceFunctionAttrs.h"
#include "llvm/Transforms/IPO/FunctionAttrs.h"
#include "llvm/Transforms/IPO/GlobalDCE.h"
#include "llvm/Transforms/IPO/GlobalOpt.h"
#include "llvm/Transforms/IPO/GlobalSplit.h"
#include "llvm/Transforms/IPO/HotColdSplitting.h"
#include "llvm/Transforms/IPO/IROutliner.h"
#include "llvm/Transforms/IPO/InferFunctionAttrs.h"
#include "llvm/Transforms/IPO/Inliner.h"
#include "llvm/Transforms/IPO/LowerTypeTests.h"
// #include "llvm/Transforms/IPO/MemProfContextDisambiguation.h"
#include "llvm/Analysis/ValueLattice.h"
#include "llvm/Transforms/IPO/MergeFunctions.h"
#include "llvm/Transforms/IPO/ModuleInliner.h"
#include "llvm/Transforms/IPO/OpenMPOpt.h"
#include "llvm/Transforms/IPO/PartialInlining.h"
#include "llvm/Transforms/IPO/SCCP.h"
#include "llvm/Transforms/IPO/SampleProfile.h"
#include "llvm/Transforms/IPO/SampleProfileProbe.h"
#include "llvm/Transforms/IPO/SyntheticCountsPropagation.h"
#include "llvm/Transforms/IPO/WholeProgramDevirt.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Instrumentation/CGProfile.h"
#include "llvm/Transforms/Instrumentation/ControlHeightReduction.h"
#include "llvm/Transforms/Instrumentation/InstrOrderFile.h"
#include "llvm/Transforms/Instrumentation/InstrProfiling.h"
#include "llvm/Transforms/Instrumentation/MemProfiler.h"
#include "llvm/Transforms/Instrumentation/PGOInstrumentation.h"
#include "llvm/Transforms/Scalar/ADCE.h"
#include "llvm/Transforms/Scalar/AlignmentFromAssumptions.h"
#include "llvm/Transforms/Scalar/AnnotationRemarks.h"
#include "llvm/Transforms/Scalar/BDCE.h"
#include "llvm/Transforms/Scalar/CallSiteSplitting.h"
#include "llvm/Transforms/Scalar/ConstraintElimination.h"
#include "llvm/Transforms/Scalar/CorrelatedValuePropagation.h"
#include "llvm/Transforms/Scalar/DFAJumpThreading.h"
#include "llvm/Transforms/Scalar/DeadStoreElimination.h"
#include "llvm/Transforms/Scalar/DivRemPairs.h"
#include "llvm/Transforms/Scalar/EarlyCSE.h"
#include "llvm/Transforms/Scalar/Float2Int.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/Transforms/Scalar/IndVarSimplify.h"
#include "llvm/Transforms/Scalar/InstSimplifyPass.h"
#include "llvm/Transforms/Scalar/JumpThreading.h"
#include "llvm/Transforms/Scalar/LICM.h"
#include "llvm/Transforms/Scalar/LoopDeletion.h"
#include "llvm/Transforms/Scalar/LoopDistribute.h"
#include "llvm/Transforms/Scalar/LoopFlatten.h"
#include "llvm/Transforms/Scalar/LoopIdiomRecognize.h"
#include "llvm/Transforms/Scalar/LoopInstSimplify.h"
#include "llvm/Transforms/Scalar/LoopInterchange.h"
#include "llvm/Transforms/Scalar/LoopLoadElimination.h"
#include "llvm/Transforms/Scalar/LoopPassManager.h"
#include "llvm/Transforms/Scalar/LoopRotation.h"
#include "llvm/Transforms/Scalar/LoopSimplifyCFG.h"
#include "llvm/Transforms/Scalar/LoopSink.h"
#include "llvm/Transforms/Scalar/LoopUnrollAndJamPass.h"
#include "llvm/Transforms/Scalar/LoopUnrollPass.h"
#include "llvm/Transforms/Scalar/LoopVersioningLICM.h"
#include "llvm/Transforms/Scalar/LowerConstantIntrinsics.h"
#include "llvm/Transforms/Scalar/LowerExpectIntrinsic.h"
#include "llvm/Transforms/Scalar/LowerMatrixIntrinsics.h"
#include "llvm/Transforms/Scalar/MemCpyOptimizer.h"
#include "llvm/Transforms/Scalar/MergedLoadStoreMotion.h"
#include "llvm/Transforms/Scalar/NewGVN.h"
#include "llvm/Transforms/Scalar/Reassociate.h"
#include "llvm/Transforms/Scalar/SCCP.h"
#include "llvm/Transforms/Scalar/SROA.h"
#include "llvm/Transforms/Scalar/SimpleLoopUnswitch.h"
#include "llvm/Transforms/Scalar/SimplifyCFG.h"
#include "llvm/Transforms/Scalar/SpeculativeExecution.h"
#include "llvm/Transforms/Scalar/TailRecursionElimination.h"
#include "llvm/Transforms/Scalar/WarnMissedTransforms.h"
#include "llvm/Transforms/Utils/AddDiscriminators.h"
#include "llvm/Transforms/Utils/AssumeBundleBuilder.h"
#include "llvm/Transforms/Utils/CanonicalizeAliases.h"
#include "llvm/Transforms/Utils/SCCPSolver.h"

// #include "llvm/Transforms/Utils/CountVisits.h"
#include "llvm/Transforms/Utils/InjectTLIMappings.h"
#include "llvm/Transforms/Utils/LibCallsShrinkWrap.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"
// #include "llvm/Transforms/Utils/MoveAutoInit.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/ConstantRange.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/NameAnonGlobals.h"
#include "llvm/Transforms/Utils/RelLookupTableConverter.h"
#include "llvm/Transforms/Utils/SimplifyCFGOptions.h"
#include "llvm/Transforms/Vectorize/LoopVectorize.h"
#include "llvm/Transforms/Vectorize/SLPVectorizer.h"
#include "llvm/Transforms/Vectorize/VectorCombine.h"

using namespace std;
using namespace llvm;

#if LLVM_VERSION_MAJOR < 17
inline llvm::raw_ostream& operator<<(llvm::raw_ostream& OS,
                                     const llvm::KnownBits& KB) {
  KB.print(OS);
  return OS;
}
#endif

#define RIP 0x007FFFFFFF400000
#define STACKP_VALUE 0x14FF28

using ReverseRegisterMap = DenseMap<Value*, int>;
using RegisterMap = DenseMap<int, Value*>;
// BB start address, BB pointer, Final registers in that RegisterMap so we can
// use it later
using BBInfo = tuple<uint64_t, BasicBlock*, RegisterMap>;

enum FlagOperation { SET_VALUE, SET_ONE, SET_ZERO, TOGGLE };

enum Flag {
  FLAG_CF = 0,        // Carry flag
  FLAG_RESERVED1 = 1, // Reserved, typically not used by programs
  FLAG_PF = 2,        // Parity flag
  FLAG_RESERVED3 = 3, // Reserved, typically not used by programs
  FLAG_AF = 4,        // Adjust flag
  FLAG_RESERVED5 = 5, // Reserved, typically not used by programs
  FLAG_ZF = 6,        // Zero flag
  FLAG_SF = 7,        // Sign flag
  FLAG_TF = 8,        // Trap flag
  FLAG_IF = 9,        // Interrupt enable flag
  FLAG_DF = 10,       // Direction flag
  FLAG_OF = 11,       // Overflow flag
  FLAG_IOPL =
      12, // I/O privilege level (286+ only) always all-1s on 8086 and 186
  FLAG_IOPL2 =
      13,       // I/O privilege level (286+ only) always all-1s on 8086 and 186
  FLAG_NT = 14, // Nested task flag (286+ only), always 1 on 8086 and 186
  FLAG_MD = 15, // Mode flag (NEC V-series only), reserved on all Intel CPUs.
                // Always 1 on 8086 / 186, 0 on 286 and later.
  FLAG_RF = 16, // Resume flag (386+ only)
  FLAG_VM = 17, // Virtual 8086 mode flag (386+ only)
  FLAG_AC = 18, // Alignment Check (486+, ring 3),
  FLAG_VIF = 19,   // Virtual interrupt flag (Pentium+)
  FLAG_VIP = 20,   // Virtual interrupt pending (Pentium+)
  FLAG_ID = 21,    // Able to use CPUID instruction (Pentium+)
  FLAG_RES22 = 22, //  Reserved, typically not used by programs
  FLAG_RES23 = 23, //  Reserved, typically not used by programs
  FLAG_RES24 = 24, //  Reserved, typically not used by programs
  FLAG_RES25 = 25, //  Reserved, typically not used by programs
  FLAG_RES26 = 26, //  Reserved, typically not used by programs
  FLAG_RES27 = 27, //  Reserved, typically not used by programs
  FLAG_RES28 = 28, //  Reserved, typically not used by programs
  FLAG_RES29 = 29, //  Reserved, typically not used by programs
  FLAG_AES = 30,   // AES key schedule loaded flag
  FLAG_AI = 31,    // Alternate Instruction Set enabled
  // reserved above 32-63
  FLAGS_END = 32
};

enum opaque_info { NOT_OPAQUE = 0, OPAQUE_TRUE = 1, OPAQUE_FALSE = 2 };

enum ROP_info {
  ROP_return = 0,
  REAL_return = 1,
};

enum JMP_info {
  JOP_jmp = 0,
  JOP_jmp_unsolved = 1,
};

enum PATH_info {
  PATH_unsolved = 0,
  PATH_solved = 1,
};

// 8 << (arg.argtype.size - 1)
enum ArgType { NONE = 0, I8 = 1, I16 = 2, I32 = 3, I64 = 4 };