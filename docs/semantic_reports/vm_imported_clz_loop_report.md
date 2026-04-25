# vm_imported_clz_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_imported_clz_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_imported_clz_loop.ll`
- **Symbol:** `vm_imported_clz_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_imported_clz_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_imported_clz_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 31 | 31 | 31 | yes | limit=1, v=1: clz=31 |
| 2 | RCX=1 | 57 | 57 | 57 | yes | limit=2 |
| 3 | RCX=7 | 197 | 197 | 197 | yes | limit=8 |
| 4 | RCX=255 | 192 | 192 | 192 | yes | 0xFF |
| 5 | RCX=170 | 72 | 72 | 72 | yes | 0xAA: limit=3 |
| 6 | RCX=85 | 147 | 147 | 147 | yes | 0x55: limit=6 |
| 7 | RCX=65535 | 128 | 128 | 128 | yes | 0xFFFF |
| 8 | RCX=74565 | 90 | 90 | 90 | yes | 0x12345 |
| 9 | RCX=11259375 | 64 | 64 | 64 | yes | 0xABCDEF |
| 10 | RCX=-889275714 | 0 | 0 | 0 | yes | 0xCAFEBABE: top bit set, all clz=0 |

## Source

```c
/* PC-state VM whose body calls __builtin_clz (lowered by clang to
 * @llvm.ctlz.i32) on different transforms of x.
 * Lift target: vm_imported_clz_loop_target.
 * Goal: cover a third recognized-intrinsic shape (after abs and popcount).
 * The argument is OR'd with 1 to keep clz well-defined.
 */
#include <stdio.h>

enum CzVmPc {
    CZ_LOAD       = 0,
    CZ_INIT       = 1,
    CZ_CHECK      = 2,
    CZ_BODY_XOR   = 3,
    CZ_BODY_OR    = 4,
    CZ_BODY_CALL  = 5,
    CZ_BODY_ADD   = 6,
    CZ_BODY_INC   = 7,
    CZ_HALT       = 8,
};

__declspec(noinline)
int vm_imported_clz_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int v     = 0;
    int cnt   = 0;
    int pc    = CZ_LOAD;

    while (1) {
        if (pc == CZ_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = CZ_INIT;
        } else if (pc == CZ_INIT) {
            idx = 0;
            pc = CZ_CHECK;
        } else if (pc == CZ_CHECK) {
            pc = (idx < limit) ? CZ_BODY_XOR : CZ_HALT;
        } else if (pc == CZ_BODY_XOR) {
            v = x ^ (idx * 0x37);
            pc = CZ_BODY_OR;
        } else if (pc == CZ_BODY_OR) {
            v = v | 1;
            pc = CZ_BODY_CALL;
        } else if (pc == CZ_BODY_CALL) {
            cnt = __builtin_clz((unsigned)v);
            pc = CZ_BODY_ADD;
        } else if (pc == CZ_BODY_ADD) {
            sum = sum + cnt;
            pc = CZ_BODY_INC;
        } else if (pc == CZ_BODY_INC) {
            idx = idx + 1;
            pc = CZ_CHECK;
        } else if (pc == CZ_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_imported_clz_loop(0xFF)=%d vm_imported_clz_loop(0xCAFEBABE)=%d\n",
           vm_imported_clz_loop_target(0xFF),
           vm_imported_clz_loop_target((int)0xCAFEBABEu));
    return 0;
}
```
