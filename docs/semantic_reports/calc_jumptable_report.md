# calc_jumptable - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/calc_jumptable.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/calc_jumptable.ll`
- **Symbol:** `calc_jumptable`
- **Native driver:** `rewrite-regression-work/eq/calc_jumptable_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `calc_jumptable` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=-1 | 4294967295 | 4294967295 | 4294967295 | yes | default (negative) |
| 2 | RCX=0 | 1 | 1 | 1 | yes | 2^0 |
| 3 | RCX=1 | 2 | 2 | 2 | yes | 2^1 |
| 4 | RCX=2 | 4 | 4 | 4 | yes | 2^2 |
| 5 | RCX=3 | 8 | 8 | 8 | yes | 2^3 |
| 6 | RCX=4 | 16 | 16 | 16 | yes | 2^4 |
| 7 | RCX=5 | 32 | 32 | 32 | yes | 2^5 |
| 8 | RCX=6 | 64 | 64 | 64 | yes | 2^6 |
| 9 | RCX=7 | 128 | 128 | 128 | yes | 2^7 |
| 10 | RCX=8 | 256 | 256 | 256 | yes | 2^8 |
| 11 | RCX=9 | 512 | 512 | 512 | yes | 2^9 |
| 12 | RCX=10 | 4294967295 | 4294967295 | 4294967295 | yes | default (above range) |

## Source

```c
/* Jump table test: MSVC /O2 should emit a real jump table for 7+ dense cases.
 * Lift target: calc_jumptable
 * Expected IR: switch (or equivalent multi-target branch) on symbolic input.
 *
 * NOTE: Must be compiled with /O2 (not /Od) to generate jmp [table + reg*8].
 * /Od generates compare chains which the lifter already handles. */

#include <stdio.h>

__declspec(noinline)
int calc_jumptable(int op) {
    switch (op) {
    case 0: return 1;
    case 1: return 2;
    case 2: return 4;
    case 3: return 8;
    case 4: return 16;
    case 5: return 32;
    case 6: return 64;
    case 7: return 128;
    case 8: return 256;
    case 9: return 512;
    default: return -1;
    }
}

int main(void) {
    printf("jt(0)=%d jt(5)=%d jt(9)=%d jt(99)=%d\n",
           calc_jumptable(0), calc_jumptable(5),
           calc_jumptable(9), calc_jumptable(99));
    return 0;
}
```
