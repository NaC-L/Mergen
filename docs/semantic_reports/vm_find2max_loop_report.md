# vm_find2max_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 11/11 equivalent
- **Source:** `testcases/rewrite_smoke/vm_find2max_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_find2max_loop.ll`
- **Symbol:** `vm_find2max_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_find2max_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_find2max_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 41 | 41 | 41 | yes | limit=2, data=[0,0x29] |
| 2 | RCX=1 | 10323 | 10323 | 10323 | yes | limit=3 |
| 3 | RCX=2 | 20601 | 20601 | 20601 | yes | limit=4 |
| 4 | RCX=7 | 51953 | 51953 | 51953 | yes | limit=9 |
| 5 | RCX=170 | 53752 | 53752 | 53752 | yes | 0xAA |
| 6 | RCX=255 | 57599 | 57599 | 57599 | yes | 0xFF |
| 7 | RCX=85 | 41969 | 41969 | 41969 | yes | 0x55 |
| 8 | RCX=291 | 29063 | 29063 | 29063 | yes | 0x123 |
| 9 | RCX=4660 | 37113 | 37113 | 37113 | yes | 0x1234 |
| 10 | RCX=11259375 | 61424 | 61424 | 61424 | yes | 0xABCDEF |
| 11 | RCX=204 | 52453 | 52453 | 52453 | yes | 0xCC |

## Source

```c
/* PC-state VM that finds the TWO largest values in a stack array, packing
 * them as top1 | (top2 << 8).
 * Lift target: vm_find2max_loop_target.
 * Goal: cover a loop body with a three-way update on two co-related state
 * vars (top1 and top2): if v > top1 the pair shifts (t2 := t1; t1 := v),
 * else-if v > t2 only t2 updates, else neither.  Distinct from
 * vm_argmax_loop (single max+idx) and vm_minarray_loop (single min only).
 */
#include <stdio.h>

enum FmVmPc {
    FM_LOAD       = 0,
    FM_INIT_FILL  = 1,
    FM_FILL_CHECK = 2,
    FM_FILL_BODY  = 3,
    FM_FILL_INC   = 4,
    FM_INIT_SCAN  = 5,
    FM_SCAN_CHECK = 6,
    FM_SCAN_LOAD  = 7,
    FM_SCAN_TEST1 = 8,
    FM_SCAN_TEST2 = 9,
    FM_UPD_TOP1   = 10,
    FM_UPD_TOP2   = 11,
    FM_SCAN_INC   = 12,
    FM_PACK       = 13,
    FM_HALT       = 14,
};

__declspec(noinline)
int vm_find2max_loop_target(int x) {
    int data[10];
    int limit  = 0;
    int idx    = 0;
    int top1   = 0;
    int top2   = 0;
    int v      = 0;
    int result = 0;
    int pc     = FM_LOAD;

    while (1) {
        if (pc == FM_LOAD) {
            limit = (x & 7) + 2;
            top1 = 0;
            top2 = 0;
            pc = FM_INIT_FILL;
        } else if (pc == FM_INIT_FILL) {
            idx = 0;
            pc = FM_FILL_CHECK;
        } else if (pc == FM_FILL_CHECK) {
            pc = (idx < limit) ? FM_FILL_BODY : FM_INIT_SCAN;
        } else if (pc == FM_FILL_BODY) {
            data[idx] = (x ^ (idx * 0x29)) & 0xFF;
            pc = FM_FILL_INC;
        } else if (pc == FM_FILL_INC) {
            idx = idx + 1;
            pc = FM_FILL_CHECK;
        } else if (pc == FM_INIT_SCAN) {
            idx = 0;
            pc = FM_SCAN_CHECK;
        } else if (pc == FM_SCAN_CHECK) {
            pc = (idx < limit) ? FM_SCAN_LOAD : FM_PACK;
        } else if (pc == FM_SCAN_LOAD) {
            v = data[idx];
            pc = FM_SCAN_TEST1;
        } else if (pc == FM_SCAN_TEST1) {
            pc = (v > top1) ? FM_UPD_TOP1 : FM_SCAN_TEST2;
        } else if (pc == FM_SCAN_TEST2) {
            pc = (v > top2) ? FM_UPD_TOP2 : FM_SCAN_INC;
        } else if (pc == FM_UPD_TOP1) {
            top2 = top1;
            top1 = v;
            pc = FM_SCAN_INC;
        } else if (pc == FM_UPD_TOP2) {
            top2 = v;
            pc = FM_SCAN_INC;
        } else if (pc == FM_SCAN_INC) {
            idx = idx + 1;
            pc = FM_SCAN_CHECK;
        } else if (pc == FM_PACK) {
            result = top1 + (top2 << 8);
            pc = FM_HALT;
        } else if (pc == FM_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_find2max_loop(0xFF)=%d vm_find2max_loop(0xABCDEF)=%d\n",
           vm_find2max_loop_target(0xFF), vm_find2max_loop_target(0xABCDEF));
    return 0;
}
```
