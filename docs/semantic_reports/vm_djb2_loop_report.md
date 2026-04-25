# vm_djb2_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_djb2_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_djb2_loop.ll`
- **Symbol:** `vm_djb2_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_djb2_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_djb2_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 46501 | 46501 | 46501 | yes | limit=1, nib=0 |
| 2 | RCX=1 | 27238 | 27238 | 27238 | yes | limit=2, nibs=[1,0] |
| 3 | RCX=2 | 47975 | 47975 | 47975 | yes | limit=3, nibs=[2,0,0] |
| 4 | RCX=7 | 7212 | 7212 | 7212 | yes | limit=8, nibs=[7,0,..,0] |
| 5 | RCX=18 | 48008 | 48008 | 48008 | yes | 0x12: limit=3, nibs=[2,1,0] |
| 6 | RCX=291 | 48459 | 48459 | 48459 | yes | 0x123: limit=4, nibs=[3,2,1,0] |
| 7 | RCX=4660 | 4079 | 4079 | 4079 | yes | 0x1234: limit=5 |
| 8 | RCX=74565 | 57268 | 57268 | 57268 | yes | 0x12345: limit=6 |
| 9 | RCX=16777215 | 40191 | 40191 | 40191 | yes | all F: limit=8 |
| 10 | RCX=11259375 | 32432 | 32432 | 32432 | yes | 0xABCDEF: limit=8 |
| 11 | RCX=85 | 19055 | 19055 | 19055 | yes | 0x55: limit=6 |
| 12 | RCX=170 | 57017 | 57017 | 57017 | yes | 0xAA: limit=3 |

## Source

```c
/* PC-state VM running a DJB2-style hash recurrence:
 *   hash = (hash * 33 + nibble) & 0xFFFF
 * over the low (limit*4) bits of x.
 * Lift target: vm_djb2_loop_target.
 * Goal: cover a multiplicative-then-additive recurrence with symbolic input
 * shape (each iteration consumes a different nibble).  Distinct from
 * vm_lcg_loop (no per-iter input) and vm_polynomial_loop (constant
 * coefficient array).
 */
#include <stdio.h>

enum DjVmPc {
    DJ_LOAD       = 0,
    DJ_INIT       = 1,
    DJ_CHECK      = 2,
    DJ_BODY_NIB   = 3,
    DJ_BODY_MUL   = 4,
    DJ_BODY_ADD   = 5,
    DJ_BODY_INC   = 6,
    DJ_HALT       = 7,
};

__declspec(noinline)
int vm_djb2_loop_target(int x) {
    int hash  = 0;
    int limit = 0;
    int idx   = 0;
    int nib   = 0;
    int prod  = 0;
    int shift = 0;
    int pc    = DJ_LOAD;

    while (1) {
        if (pc == DJ_LOAD) {
            limit = (x & 7) + 1;
            hash = 5381;
            idx = 0;
            pc = DJ_INIT;
        } else if (pc == DJ_INIT) {
            pc = DJ_CHECK;
        } else if (pc == DJ_CHECK) {
            pc = (idx < limit) ? DJ_BODY_NIB : DJ_HALT;
        } else if (pc == DJ_BODY_NIB) {
            shift = idx * 4;
            nib = (x >> shift) & 0xF;
            pc = DJ_BODY_MUL;
        } else if (pc == DJ_BODY_MUL) {
            prod = hash * 33;
            pc = DJ_BODY_ADD;
        } else if (pc == DJ_BODY_ADD) {
            hash = (prod + nib) & 0xFFFF;
            pc = DJ_BODY_INC;
        } else if (pc == DJ_BODY_INC) {
            idx = idx + 1;
            pc = DJ_CHECK;
        } else if (pc == DJ_HALT) {
            return hash;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_djb2_loop(0x12345)=%d vm_djb2_loop(0xABCDEF)=%d\n",
           vm_djb2_loop_target(0x12345), vm_djb2_loop_target(0xABCDEF));
    return 0;
}
```
