# vm_imported_bsf_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_imported_bsf_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_imported_bsf_loop.ll`
- **Symbol:** `vm_imported_bsf_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_imported_bsf_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_imported_bsf_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | limit=1, x=0: bsf(0)=ok=0 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | limit=2: bit_index always 0 |
| 3 | RCX=7 | 0 | 0 | 0 | yes | limit=8 |
| 4 | RCX=255 | 0 | 0 | 0 | yes | 0xFF |
| 5 | RCX=51966 | 11 | 11 | 11 | yes | 0xCAFE: limit=7 |
| 6 | RCX=43981 | 0 | 0 | 0 | yes | 0xABCD: limit=6 |
| 7 | RCX=74565 | 0 | 0 | 0 | yes | 0x12345: limit=6 |
| 8 | RCX=-2147483641 | 0 | 0 | 0 | yes | 0x80000007 |
| 9 | RCX=-1 | 0 | 0 | 0 | yes | all F |
| 10 | RCX=-559038737 | 0 | 0 | 0 | yes | 0xDEADBEEF |
| 11 | RCX=66 | 2 | 2 | 2 | yes | 0x42: limit=3 |
| 12 | RCX=132 | 6 | 6 | 6 | yes | 0x84: limit=5 |

## Source

```c
/* PC-state VM whose body calls _BitScanForward (MSVC intrinsic) inside the
 * dispatcher, accumulating the bit-position outputs.
 * Lift target: vm_imported_bsf_loop_target.
 * Goal: cover an intrinsic that returns its result via OUTPUT POINTER (the
 * unsigned long * arg).  Distinct from the previous direct-return
 * intrinsics because the lifter has to model both the call and the
 * subsequent stack-load that picks up the result.
 */
#include <stdio.h>
#include <intrin.h>

enum BfVmPc {
    BF_LOAD       = 0,
    BF_INIT       = 1,
    BF_CHECK      = 2,
    BF_BODY_VAL   = 3,
    BF_BODY_CALL  = 4,
    BF_BODY_TEST  = 5,
    BF_BODY_ADD   = 6,
    BF_BODY_INC   = 7,
    BF_HALT       = 8,
};

__declspec(noinline)
int vm_imported_bsf_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    unsigned v = 0;
    unsigned long bit_index = 0;
    unsigned char ok = 0;
    int pc    = BF_LOAD;

    while (1) {
        if (pc == BF_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = BF_INIT;
        } else if (pc == BF_INIT) {
            idx = 0;
            pc = BF_CHECK;
        } else if (pc == BF_CHECK) {
            pc = (idx < limit) ? BF_BODY_VAL : BF_HALT;
        } else if (pc == BF_BODY_VAL) {
            v = ((unsigned)x ^ (unsigned)(idx * 0x42));
            pc = BF_BODY_CALL;
        } else if (pc == BF_BODY_CALL) {
            ok = _BitScanForward(&bit_index, v);
            pc = BF_BODY_TEST;
        } else if (pc == BF_BODY_TEST) {
            if (ok) sum = sum + (int)bit_index;
            pc = BF_BODY_INC;
        } else if (pc == BF_BODY_INC) {
            idx = idx + 1;
            pc = BF_CHECK;
        } else if (pc == BF_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_bsf_loop(0xCAFE)=%d vm_imported_bsf_loop(0x84)=%d\n",
           vm_imported_bsf_loop_target(0xCAFE),
           vm_imported_bsf_loop_target(0x84));
    return 0;
}
```
