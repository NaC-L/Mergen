# vm_ctz_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_ctz_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_ctz_loop.ll`
- **Symbol:** `vm_ctz_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_ctz_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_ctz_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 32 | 32 | 32 | yes | v=0: cap at 32 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | v=1: 0 trailing zeros |
| 3 | RCX=2 | 1 | 1 | 1 | yes | v=2 |
| 4 | RCX=4 | 2 | 2 | 2 | yes | v=4 |
| 5 | RCX=7 | 0 | 0 | 0 | yes | v=7: low bit set |
| 6 | RCX=256 | 8 | 8 | 8 | yes | v=0x100 |
| 7 | RCX=512 | 9 | 9 | 9 | yes | v=0x200 |
| 8 | RCX=65535 | 0 | 0 | 0 | yes | 0xFFFF: low bit set |
| 9 | RCX=49152 | 14 | 14 | 14 | yes | 0xC000 |
| 10 | RCX=-2147483648 | 31 | 31 | 31 | yes | 0x80000000: only top bit |
| 11 | RCX=-8 | 3 | 3 | 3 | yes | 0xFFFFFFF8: low 3 zeros |
| 12 | RCX=65536 | 16 | 16 | 16 | yes | 0x10000 |

## Source

```c
/* PC-state VM that counts trailing zero bits in x (capped at 32).
 * Lift target: vm_ctz_loop_target.
 * Goal: cover a counted loop with EARLY BREAK on LSB-set predicate.  Loop
 * counter doubles as both trip count and result.  Distinct from
 * vm_kernighan_loop (which counts set bits, not trailing-zero position) and
 * vm_palindrome_loop (which has two distinct halt PCs).
 */
#include <stdio.h>

enum CzVmPc {
    CZ_LOAD       = 0,
    CZ_INIT       = 1,
    CZ_CHECK_LIM  = 2,
    CZ_TEST_LSB   = 3,
    CZ_BODY_SHR   = 4,
    CZ_BODY_INC   = 5,
    CZ_HALT       = 6,
};

__declspec(noinline)
int vm_ctz_loop_target(int x) {
    int v     = 0;
    int count = 0;
    int pc    = CZ_LOAD;

    while (1) {
        if (pc == CZ_LOAD) {
            v = x;
            count = 0;
            pc = CZ_INIT;
        } else if (pc == CZ_INIT) {
            pc = CZ_CHECK_LIM;
        } else if (pc == CZ_CHECK_LIM) {
            pc = (count < 32) ? CZ_TEST_LSB : CZ_HALT;
        } else if (pc == CZ_TEST_LSB) {
            pc = ((v & 1) != 0) ? CZ_HALT : CZ_BODY_SHR;
        } else if (pc == CZ_BODY_SHR) {
            v = (int)((unsigned)v >> 1);
            pc = CZ_BODY_INC;
        } else if (pc == CZ_BODY_INC) {
            count = count + 1;
            pc = CZ_CHECK_LIM;
        } else if (pc == CZ_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_ctz_loop(0xC000)=%d vm_ctz_loop(0x10000)=%d\n",
           vm_ctz_loop_target(0xC000), vm_ctz_loop_target(0x10000));
    return 0;
}
```
