# calc_sum_array - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 1/1 equivalent
- **Source:** `testcases/rewrite_smoke/calc_sum_array.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_sum_array.ll`
- **Symbol:** `calc_sum_array`
- **Native driver:** `rewrite-regression-work/eq/calc_sum_array_eq.exe`
- **Lifted signature:** `define noundef i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `calc_sum_array` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | _(none)_ | 150 | 150 | 150 | yes | constant: 10+20+30+40+50 |

## Source

```c
/* Sum a small constant stack-allocated array.
 * Lift target: calc_sum_array — concrete loop + stack array access.
 * 10 + 20 + 30 + 40 + 50 = 150.
 * Tests compiler-generated array init + indexed load in a loop. */
#include <stdio.h>

__declspec(noinline)
int calc_sum_array(void) {
    int arr[] = {10, 20, 30, 40, 50};
    int sum = 0;
    for (int i = 0; i < 5; i++)
        sum += arr[i];
    return sum;
}

int main(void) {
    printf("sum([10,20,30,40,50])=%d\n", calc_sum_array());
    return 0;
}
```
