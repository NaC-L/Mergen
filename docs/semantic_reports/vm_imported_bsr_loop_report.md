# vm_imported_bsr_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_imported_bsr_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_imported_bsr_loop.ll`
- **Symbol:** `vm_imported_bsr_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_imported_bsr_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_imported_bsr_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, x=0: bsr ok=0 |
| 2 | RCX=1 | 7 | 7 | 7 | yes | limit=2: 0+7 |
| 3 | RCX=7 | 61 | 61 | 61 | yes | limit=8 |
| 4 | RCX=255 | 65 | 65 | 65 | yes | 0xFF: limit=8 |
| 5 | RCX=51966 | 105 | 105 | 105 | yes | 0xCAFE: limit=7 |
| 6 | RCX=43981 | 90 | 90 | 90 | yes | 0xABCD: limit=6 |
| 7 | RCX=74565 | 96 | 96 | 96 | yes | 0x12345: limit=6 |
| 8 | RCX=-2147483641 | 248 | 248 | 248 | yes | 0x80000007: top bit always set |
| 9 | RCX=-1 | 248 | 248 | 248 | yes | all F |
| 10 | RCX=-559038737 | 248 | 248 | 248 | yes | 0xDEADBEEF |
| 11 | RCX=128 | 7 | 7 | 7 | yes | 0x80: limit=1 |
| 12 | RCX=16 | 4 | 4 | 4 | yes | 0x10: limit=1, bit 4 |

## Source

```c
/* PC-state VM whose body calls _BitScanReverse (MSVC intrinsic with output-
 * pointer arg) inside the dispatcher.
 * Lift target: vm_imported_bsr_loop_target.
 * Goal: cover the leading-zero counterpart to vm_imported_bsf_loop.  Both
 * MSVC bit-scan intrinsics use an output-pointer arg; this exercises the
 * other direction (high-bit position via 31 - clz).
 */
#include <stdio.h>
#include <intrin.h>

enum BrVmPc {
    BR_LOAD       = 0,
    BR_INIT       = 1,
    BR_CHECK      = 2,
    BR_BODY_VAL   = 3,
    BR_BODY_CALL  = 4,
    BR_BODY_TEST  = 5,
    BR_BODY_ADD   = 6,
    BR_BODY_INC   = 7,
    BR_HALT       = 8,
};

__declspec(noinline)
int vm_imported_bsr_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    unsigned v = 0;
    unsigned long bit_index = 0;
    unsigned char ok = 0;
    int pc    = BR_LOAD;

    while (1) {
        if (pc == BR_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = BR_INIT;
        } else if (pc == BR_INIT) {
            idx = 0;
            pc = BR_CHECK;
        } else if (pc == BR_CHECK) {
            pc = (idx < limit) ? BR_BODY_VAL : BR_HALT;
        } else if (pc == BR_BODY_VAL) {
            v = ((unsigned)x ^ (unsigned)(idx * 0x91));
            pc = BR_BODY_CALL;
        } else if (pc == BR_BODY_CALL) {
            ok = _BitScanReverse(&bit_index, v);
            pc = BR_BODY_TEST;
        } else if (pc == BR_BODY_TEST) {
            if (ok) sum = sum + (int)bit_index;
            pc = BR_BODY_INC;
        } else if (pc == BR_BODY_INC) {
            idx = idx + 1;
            pc = BR_CHECK;
        } else if (pc == BR_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_bsr_loop(0xCAFE)=%d vm_imported_bsr_loop(0xDEADBEEF)=%d\n",
           vm_imported_bsr_loop_target(0xCAFE),
           vm_imported_bsr_loop_target((int)0xDEADBEEFu));
    return 0;
}
```
