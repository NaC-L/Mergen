# calc_sum_to_n - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 6/6 equivalent
- **Source:** `testcases/rewrite_smoke/calc_sum_to_n.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_sum_to_n.ll`
- **Symbol:** `calc_sum_to_n`
- **Native driver:** `rewrite-regression-work/eq/calc_sum_to_n_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `calc_sum_to_n` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | n=0 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | n=1 |
| 3 | RCX=5 | 10 | 10 | 10 | yes | 0+1+2+3+4 |
| 4 | RCX=10 | 45 | 45 | 45 | yes | 0..9 |
| 5 | RCX=32 | 496 | 496 | 496 | yes | 0..31 |
| 6 | RCX=100 | 496 | 496 | 496 | yes | clamped to 32 |

## Source

```c
/* Symbolic trip-count counted loop.
 * Lift target: calc_sum_to_n — symbolic loop bound with a clamp.
 * Goal: preserve real loop structure (phi/backedge/compare), not constant-fold.
 */
#include <stdio.h>

__declspec(noinline)
int calc_sum_to_n(int n) {
    if (n > 32)
        n = 32;

    int sum = 0;
    for (int i = 0; i < n; i++)
        sum += i;

    return sum;
}

int main(void) {
    printf("sum_to_n(5)=%d sum_to_n(10)=%d\n",
           calc_sum_to_n(5), calc_sum_to_n(10));
    return 0;
}
```
