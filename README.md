# Project Overview:
Mergen is a tool engineered to convert Assembly code into LLVM Intermediate Representation (IR).
This tool is designed for:
- The deobfuscation or devirtualization of obfuscated binary code
- The enhancement of the reverse engineering process, making it more efficient and effective, especially for complex software systems.

## Core Objectives:

### Deobfuscation

### Devirtualization

### Optimization

## Diagram
![image](https://github.com/loneicewolf/Mergen/assets/68499986/d557b048-9c77-49f2-82b2-ef299bc783c8)

## Example

This is our target program

```cpp
int maths(int a, int b, int c) {
    return a + b - c;
}
```

![image](images/Original_Asm_Code.PNG)

VMProtect settings, everything is turned off, we virtualize the function on ultra setting. (Tested versions 3.4.0-3.6.0) 

![image](images/vmp_settings.PNG)

![image](images/vmp_settings2.PNG)

This is how it looks after virtualizing.

![image](images/vmp_ultra_asm.PNG)

Here, we run mergen. First argument is the name of the file and the second argument is the address of the function. Look how simple it is to run. And we can compile the output so we can explore it using our favorite decompiler.

![image](images/mergen_run.PNG)

```llvm
; ModuleID = 'my_lifting_module'
source_filename = "my_lifting_module"

; Function Attrs: mustprogress nofree norecurse nosync nounwind willreturn memory(none)
define i64 @main(i64 %rax, i64 %rcx, i64 %rdx, i64 %rbx, i64 %0, i64 %rbp, i64 %rsi, i64 %rdi, i64 %r8, i64 %r9, i64 %r10, i64 %r11, i64 %r12, i64 %r13, i64 %r14, i64 %r15, ptr nocapture readnone %memory) local_unnamed_addr #0 {
entry:
  %stackmemory = alloca i128, i128 20971520, align 8
  %1 = trunc i64 %r8 to i32
  %2 = trunc i64 %rdx to i32
  %3 = trunc i64 %rcx to i32
  %realadd-5369234850- = add i32 %2, %3
  %not17196 = sub i32 %realadd-5369234850-, %1
  %4 = zext i32 %not17196 to i64
  ret i64 %4
}

attributes #0 = { mustprogress nofree norecurse nosync nounwind willreturn memory(none) }
```

After compiling:

![image](images/disass.PNG)

![image](images/decomp.PNG)

Now you might notice the registers are a little bit off. This is because of we dont follow the calling conventions, if we were to follow the calling conventions, function signature would look like this:
```llvm
define i64 @main(i64 %rcx, i64 %rdx, i64 %rdx, i64 %r8, i64 %r9 ...) 
```
So, we just adjust the function signature to look normally. If you have more questions about this part, I suggest you research [calling conventions](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170#parameter-passing) and [ABI](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170&source=recommendations#register-volatility-and-preservation).

![image](images/decomp2.PNG)

![image](images/adjusted.PNG)

## What it can/cant do

### It can devirtualize some versions of some programs. 

### It can figure out if `jcc` is opaque.

### It cant decide which path to follow if `jcc` is not opaque.

### It cant optimize whole binary, only one function at a time. 



# Getting in touch
Join our [Mergen Discord Server](https://discord.gg/e3eftYguqB) to trade ideas or just chatting in general.
