# vm_imported_cttz_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_imported_cttz_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_imported_cttz_loop.ll`
- **Symbol:** `vm_imported_cttz_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_imported_cttz_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_imported_cttz_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 30 | 30 | 30 | yes | limit=1, x=0 |
| 2 | RCX=1 | 4 | 4 | 4 | yes | limit=2, x=1 |
| 3 | RCX=7 | 8 | 8 | 8 | yes | limit=8 |
| 4 | RCX=255 | 7 | 7 | 7 | yes | 0xFF: limit=8 |
| 5 | RCX=256 | 8 | 8 | 8 | yes | 0x100: limit=1 |
| 6 | RCX=51966 | 7 | 7 | 7 | yes | 0xCAFE: limit=7 |
| 7 | RCX=43981 | 6 | 6 | 6 | yes | 0xABCD: limit=6 |
| 8 | RCX=74565 | 7 | 7 | 7 | yes | 0x12345: limit=6 |
| 9 | RCX=-1 | 7 | 7 | 7 | yes | all F |
| 10 | RCX=-559038737 | 7 | 7 | 7 | yes | 0xDEADBEEF |
| 11 | RCX=128 | 7 | 7 | 7 | yes | 0x80: limit=1 |

## Source

```c
/* PC-state VM whose body calls __builtin_ctz (lowered to @llvm.cttz.i32) on
 * x XOR'd with a per-iteration constant.
 * Lift target: vm_imported_cttz_loop_target.
 * Goal: cover a fifth recognized-intrinsic shape.  cttz exercises the
 * trailing-zero count side of the bit-scan family (after vm_imported_clz_loop).
 * Argument is OR'd with a high bit to keep cttz well-defined.
 */
#include <stdio.h>

enum CtVmPc {
    CT_LOAD       = 0,
    CT_INIT       = 1,
    CT_CHECK      = 2,
    CT_BODY_XOR   = 3,
    CT_BODY_OR    = 4,
    CT_BODY_CALL  = 5,
    CT_BODY_ADD   = 6,
    CT_BODY_INC   = 7,
    CT_HALT       = 8,
};

__declspec(noinline)
int vm_imported_cttz_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int v     = 0;
    int cnt   = 0;
    int pc    = CT_LOAD;

    while (1) {
        if (pc == CT_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = CT_INIT;
        } else if (pc == CT_INIT) {
            idx = 0;
            pc = CT_CHECK;
        } else if (pc == CT_CHECK) {
            pc = (idx < limit) ? CT_BODY_XOR : CT_HALT;
        } else if (pc == CT_BODY_XOR) {
            v = x ^ (idx * 0x91);
            pc = CT_BODY_OR;
        } else if (pc == CT_BODY_OR) {
            v = v | 0x40000000;
            pc = CT_BODY_CALL;
        } else if (pc == CT_BODY_CALL) {
            cnt = __builtin_ctz((unsigned)v);
            pc = CT_BODY_ADD;
        } else if (pc == CT_BODY_ADD) {
            sum = sum + cnt;
            pc = CT_BODY_INC;
        } else if (pc == CT_BODY_INC) {
            idx = idx + 1;
            pc = CT_CHECK;
        } else if (pc == CT_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_cttz_loop(0xFF)=%d vm_imported_cttz_loop(0xCAFE)=%d\n",
           vm_imported_cttz_loop_target(0xFF),
           vm_imported_cttz_loop_target(0xCAFE));
    return 0;
}
```
