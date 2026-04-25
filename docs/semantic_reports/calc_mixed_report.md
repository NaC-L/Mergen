# calc_mixed - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 7/7 equivalent
- **Source:** `testcases/rewrite_smoke/calc_mixed.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_mixed.ll`
- **Symbol:** `calc_mixed`
- **Native driver:** `rewrite-regression-work/eq/calc_mixed_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `calc_mixed` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=150 | 576 | 576 | 576 | yes | x>100: (42+150)*3=576 |
| 2 | RCX=101 | 429 | 429 | 429 | yes | x>100: (42+101)*3=429 |
| 3 | RCX=0 | 126 | 126 | 126 | yes | x<=100: (42-0)*3=126 |
| 4 | RCX=1 | 123 | 123 | 123 | yes | x<=100: (42-1)*3=123 |
| 5 | RCX=42 | 0 | 0 | 0 | yes | x<=100: (42-42)*3=0 |
| 6 | RCX=50 | 4294967272 | 4294967272 | 4294967272 | yes | x<=100: uint32 wrap, zext |
| 7 | RCX=100 | 4294967122 | 4294967122 | 4294967122 | yes | x<=100: uint32 wrap, zext |

## Source

```c
/* Mixed symbolic + concrete: branch on input then multiply.
 * Lift target: calc_mixed — symbolic arg, one branch, post-merge math.
 * Expected IR: select on (x > 100), then mul by 3. */
#include <stdio.h>
#include <stdint.h>

__declspec(noinline)
int calc_mixed(int x) {
    uint32_t base = 42u;
    uint32_t ux = (uint32_t)x;
    if (x > 100)
        base += ux;
    else
        base -= ux;
    uint32_t scaled = base * 3u;
    return (int)(int32_t)scaled;
}

int main(void) {
    printf("mixed(150)=%d mixed(50)=%d\n",
           calc_mixed(150), calc_mixed(50));
    return 0;
}
```
