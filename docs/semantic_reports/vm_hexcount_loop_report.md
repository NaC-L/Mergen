# vm_hexcount_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 12/12 equivalent
- **Source:** `testcases/rewrite_smoke/vm_hexcount_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_hexcount_loop.ll`
- **Symbol:** `vm_hexcount_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_hexcount_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_hexcount_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero nibbles |
| 2 | RCX=1 | 0 | 0 | 0 | yes | only nibble 0 = 1 |
| 3 | RCX=10 | 1 | 1 | 1 | yes | 0xA: 1 letter |
| 4 | RCX=171 | 2 | 2 | 2 | yes | 0xAB: 2 letters |
| 5 | RCX=255 | 2 | 2 | 2 | yes | 0xFF: 2 letters |
| 6 | RCX=39321 | 0 | 0 | 0 | yes | 0x9999: all digit nibbles |
| 7 | RCX=4660 | 0 | 0 | 0 | yes | 0x1234: all digits |
| 8 | RCX=305419896 | 0 | 0 | 0 | yes | 0x12345678: all digits |
| 9 | RCX=-1431655766 | 8 | 8 | 8 | yes | 0xAAAAAAAA: all letters |
| 10 | RCX=-1412567296 | 6 | 6 | 6 | yes | 0xABCDEF00: 6 letters |
| 11 | RCX=-19088744 | 6 | 6 | 6 | yes | 0xFEDCBA98: 6 letters |
| 12 | RCX=-889275714 | 8 | 8 | 8 | yes | 0xCAFEBABE: 8 letters |

## Source

```c
/* PC-state VM that counts nibbles >= 10 (hex letter digits A-F) in x.
 * Lift target: vm_hexcount_loop_target.
 * Goal: cover a fixed 8-trip loop where each iteration extracts a different
 * nibble and conditionally increments a counter on a >= predicate.  Body
 * uses the always-write recipe (count += (nib >= 10)) to avoid the
 * multi-counter phi-undef bug.
 */
#include <stdio.h>

enum HcVmPc {
    HC_LOAD       = 0,
    HC_INIT       = 1,
    HC_CHECK      = 2,
    HC_BODY_NIB   = 3,
    HC_BODY_PRED  = 4,
    HC_BODY_ADD   = 5,
    HC_BODY_INC   = 6,
    HC_HALT       = 7,
};

__declspec(noinline)
int vm_hexcount_loop_target(int x) {
    int idx   = 0;
    int count = 0;
    int nib   = 0;
    int pred  = 0;
    int pc    = HC_LOAD;

    while (1) {
        if (pc == HC_LOAD) {
            idx = 0;
            count = 0;
            pc = HC_INIT;
        } else if (pc == HC_INIT) {
            pc = HC_CHECK;
        } else if (pc == HC_CHECK) {
            pc = (idx < 8) ? HC_BODY_NIB : HC_HALT;
        } else if (pc == HC_BODY_NIB) {
            nib = (x >> (idx * 4)) & 0xF;
            pc = HC_BODY_PRED;
        } else if (pc == HC_BODY_PRED) {
            pred = (nib >= 10) ? 1 : 0;
            pc = HC_BODY_ADD;
        } else if (pc == HC_BODY_ADD) {
            count = count + pred;
            pc = HC_BODY_INC;
        } else if (pc == HC_BODY_INC) {
            idx = idx + 1;
            pc = HC_CHECK;
        } else if (pc == HC_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_hexcount_loop(0xCAFEBABE)=%d vm_hexcount_loop(0x12345678)=%d\n",
           vm_hexcount_loop_target((int)0xCAFEBABEu), vm_hexcount_loop_target(0x12345678));
    return 0;
}
```
