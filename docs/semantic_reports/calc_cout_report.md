# calc_cout - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 4/4 equivalent
- **Source:** `testcases/rewrite_smoke/calc_cout.cpp`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_cout.ll`
- **Symbol:** `?calc_cout@@YAHH@Z`
- **Native driver:** `rewrite-regression-work/eq/calc_cout_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `?calc_cout@@YAHH@Z` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=10 | 37 | 37 | 37 | yes | 10*3+7 |
| 2 | RCX=0 | 7 | 7 | 7 | yes | 0*3+7 |
| 3 | RCX=100 | 307 | 307 | 307 | yes | 100*3+7 |
| 4 | RCX=1 | 10 | 10 | 10 | yes | 1*3+7 |

## Source

```cpp
/* Test: function with cout call.
 * Lift target: calc_cout — external call handling.
 * The computation is pure, but it calls cout before returning. */
#include <iostream>

__declspec(noinline)
int calc_cout(int x) {
    int result = x * 3 + 7;
    std::cout << result;
    return result;
}

int main() {
    int r = calc_cout(10);
    return r;
}
```
