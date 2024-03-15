# Project Overview:
Mergen is a sophisticated software tool engineered to convert Assembly code into LLVM Intermediate Representation (IR). This tool is specifically created for the deobfuscation or devirtualization of obfuscated binary code. It is designed to enhance the reverse engineering process, making it more efficient and effective, especially for complex software systems.

Core Objectives:

Deobfuscation

Devirtualization

Optimization


# Operational Workflow of Mergen:
1. Parsing Assembly to LLVM IR:
Initial Step: Mergen begins by parsing existing Assembly instructions into LLVM Intermediate Representation.
Process: It continues this parsing process until it encounters a jump instruction or a return. `asm_to_zydis_to_lift` parses bytes to zydis Instructions to be lifted into llvm ir in the function `liftInstruction`. 
2. Analyzing Jumps and Returns:
Jump Analysis: When a jump instruction is encountered, Mergen checks if the jump destination is a constant value.
Return Analysis: For return instructions, the tool assesses whether the ret is part of a standard function return or a Return-Oriented Programming gadget used for jumping to the next handler. This involves checking for any modifications to the instruction pointer (xIP).
3. Solving Jump Destinations:
Destination Resolution: If the jump is not to a constant or the return is identified as an ROP gadget, Mergen resolves where the control flow is intended to jump next.
4. Iterative Parsing and Analysis:
Looping Process: The tool repeats the process from step 1, parsing subsequent asm instructions into LLVM IR.
Termination Condition: This iteration continues until Mergen identifies a real `ret` instruction. A real ret is confirmed when the stack pointer (xSP) at the end of the function matches the xSP value at the start of the function.


# Demo
Releases include binary protected by VMProtect Ultimate 3.4.0, (maths function virtualized, anything else is off) and the original binary for comparison.

to execute the demo:
lifter.exe
clang output.ll -O3 
open up the output from clang and the devirtualized function is in main, type decl is 

```int __cdecl main(int rax, int rcx, int rdx, int rbx, int rsp, int rbp, int rsi, int rdi, int r8, int r9, int r10, int r11, int r12, int r13, int r14, int r15)```
(to be swapped with a struct CPUState that consists of cpu registers)




# Features we need to work on:
multiple branch support

inline/outline calls

ABI, calling conventions

better memory operations, LLVM doesnt support INTTOPTR !!!! which this code relies on unfortunately, so a (shitty) custom optimization has been written for it. However while rewriting the code, it would be better if we can come up with an alternative. I believe we can create an array that stands for RAM. It would be easier if we knew which memory we access at **everytime** but we cant assume that, it could be a pointer passed as an argument. However since VM constants are, well, constants we should always know which handler we will access


building:

[llvm branch that was used](https://github.com/llvm/llvm-project/tree/701e6f7630474b637e0bc45d009bf2ec47f2d3fd)

[zydis branch that was used](https://github.com/zyantific/zydis/tree/v4.0.0)


