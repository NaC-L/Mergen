# vm_imported_clz_loop - semantic equivalence

- **Verdict:** PASS
- **Cases:** 10/10 passed
- **Source:** `testcases/rewrite_smoke/vm_imported_clz_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_imported_clz_loop.ll`
- **Symbol:** `vm_imported_clz_loop_target`
- **IR size:** 250 lines, 1 function definitions

## Semantic cases

| # | Inputs | Expected | Actual | Result | Label |
|---|--------|----------|--------|--------|-------|
| 1 | RCX=0 | 31 | 31 | pass | limit=1, v=1: clz=31 |
| 2 | RCX=1 | 57 | 57 | pass | limit=2 |
| 3 | RCX=7 | 197 | 197 | pass | limit=8 |
| 4 | RCX=255 | 192 | 192 | pass | 0xFF |
| 5 | RCX=170 | 72 | 72 | pass | 0xAA: limit=3 |
| 6 | RCX=85 | 147 | 147 | pass | 0x55: limit=6 |
| 7 | RCX=65535 | 128 | 128 | pass | 0xFFFF |
| 8 | RCX=74565 | 90 | 90 | pass | 0x12345 |
| 9 | RCX=11259375 | 64 | 64 | pass | 0xABCDEF |
| 10 | RCX=-889275714 | 0 | 0 | pass | 0xCAFEBABE: top bit set, all clz=0 |

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
