# Project Overview:
Mergen is a sophisticated software tool engineered to convert Assembly code into LLVM Intermediate Representation (IR). This tool is specifically created for the deobfuscation or devirtualization of obfuscated binary code. It is designed to enhance the reverse engineering process, making it more efficient and effective, especially for complex software systems.

### Core Objectives:

### Deobfuscation

### Devirtualization

### Optimization


# Operational Workflow of Mergen:
1. Parsing Assembly to LLVM IR:

    Initial Step: Mergen begins by parsing existing Assembly instructions into LLVM Intermediate Representation.

    Process: It continues this parsing process until it encounters a jump instruction or a return. `asm_to_zydis_to_lift` parses bytes to zydis Instructions to be lifted into llvm ir in the function `liftInstruction`. 

2. Analyzing Jumps and Returns:

    Jump Analysis: When a jump instruction is encountered, Mergen checks if the jump destination is a constant value.

    Return Analysis: For return instructions, the tool assesses whether the `ret` is part of a standard function return or a Return-Oriented Programming gadget used for jumping to the next handler. This involves checking for any modifications to the instruction pointer (xIP).

3. Solving Jump Destinations:

    Destination Resolution: If the jump is not to a constant or the return is identified as an ROP gadget, Mergen resolves where the control flow is intended to jump next.

4. Iterative Parsing and Analysis:

    Looping Process: The tool repeats the process from step 1, parsing subsequent asm instructions into LLVM IR.

    Termination Condition: This iteration continues until Mergen identifies a real `ret` instruction. A real ret is confirmed when the stack pointer (xSP) at the end of the function matches the xSP value at the start of the function.


# Missing features:

### multiple branch support

### identifying inline/outline functions



