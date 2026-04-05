# LLVM API Cheat Sheet for Mergen Passes

Quick reference for LLVM APIs used in GEPLoadPass, PromotePseudoStackPass,
ReplaceTruncWithLoadPass, and PromotePseudoMemory.

1. **`Value::replaceAllUsesWith(Value* newVal)`**
   Replaces every use of this value with `newVal`. Does NOT touch this instruction's own operands.
   *Gotcha*: After RAUW the instruction is dead but still holds operand references — erase it or it leaks.

2. **`Instruction::eraseFromParent()`**
   Removes from the parent BasicBlock ilist and deallocates. Pointer is invalid after the call.
   *Gotcha*: Asserts `use_empty()`. RAUW first, then erase — never the reverse.

3. **`Value::use_empty()`**
   Returns true when nothing references this value.
   *Gotcha*: Check AFTER erasing/replacing all users, not before. A stale user makes this return false.

4. **`GetElementPtrInst::getPointerOperand()`**
   Returns operand 0 — the base pointer. For `gep i8, ptr %memory, i64 <off>` this is `%memory`.
   *Gotcha*: Prefer over `getOperand(getNumOperands()-2)` which breaks on multi-index GEPs.

5. **`Type::getIntegerBitWidth()`**
   Returns the bit width of an `iN` type.
   *Gotcha*: Asserts if `!isIntegerTy()`. Always guard: `if (Ty->isIntegerTy()) { ... getBitWidth ... }`.

6. **`Type::isIntegerTy()`**
   Returns true only for `iN` types. False for float, vector, pointer, void, struct, array.
   *Gotcha*: Pointer types are NOT integer types — test before calling `getIntegerBitWidth()` or `computeKnownBits`.

7. **BasicBlock iteration with erasure**
   Pattern: `for (auto it = BB.begin(); it != BB.end();) { auto* I = &*it++; /* may erase I */ }`
   *Gotcha*: `it++` must advance BEFORE any erase. A range-for (`for (auto &I : BB)`) crashes on erasure.

8. **`SmallPtrSet<T*, N>`**
   Inline-storage set for pointer deduplication. Use when collecting Instructions for deferred erasure.
   *Gotcha*: Inserting the same pointer twice is safe (returns false), but erasing a pointer twice is use-after-free. The set prevents that.

9. **`computeKnownBits(Value*, DataLayout&)`**
   Computes known-zero/known-one bit masks via ValueTracking.
   *Gotcha*: Asserts on non-integer, non-pointer types. Guard callers with `isIntegerTy() || isPointerTy()`.

10. **`PreservedAnalyses::none()` vs `::all()`**
    Return `none()` if ANY IR was modified; `all()` if the pass was a no-op.
    *Gotcha*: Returning `all()` after mutating IR silently poisons cached analyses for downstream passes.
