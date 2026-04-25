# calc_cout - original vs lifted equivalence

- **Verdict:** FAIL (4/4)
- **Cases:** 0/4 equivalent
- **Source:** `testcases/rewrite_smoke/calc_cout.cpp`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_cout.ll`
- **Symbol:** `?calc_cout@@YAHH@Z`
- **Native driver:** `rewrite-regression-work/eq/calc_cout_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `?calc_cout@@YAHH@Z` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=10 | 37 | 3737 | 37 | **no** | 10*3+7 |
| 2 | RCX=0 | 7 | 77 | 7 | **no** | 0*3+7 |
| 3 | RCX=100 | 307 | 307307 | 307 | **no** | 100*3+7 |
| 4 | RCX=1 | 10 | 1010 | 10 | **no** | 1*3+7 |

## Failure detail

### case 1: 10*3+7

- inputs: `RCX=10`
- manifest expected: `37`
- native: `3737`
- lifted: `37`

### case 2: 0*3+7

- inputs: `RCX=0`
- manifest expected: `7`
- native: `77`
- lifted: `7`

### case 3: 100*3+7

- inputs: `RCX=100`
- manifest expected: `307`
- native: `307307`
- lifted: `307`

### case 4: 1*3+7

- inputs: `RCX=1`
- manifest expected: `10`
- native: `1010`
- lifted: `10`

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
