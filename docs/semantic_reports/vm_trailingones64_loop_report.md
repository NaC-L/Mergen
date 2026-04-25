# vm_trailingones64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_trailingones64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_trailingones64_loop.ll`
- **Symbol:** `vm_trailingones64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_trailingones64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_trailingones64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: 0 trailing ones |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 |
| 3 | RCX=3 | 2 | 2 | 2 | yes | x=3: 11 |
| 4 | RCX=7 | 3 | 3 | 3 | yes | x=7: 111 |
| 5 | RCX=65534 | 0 | 0 | 0 | yes | x=0xFFFE: low bit clear |
| 6 | RCX=65535 | 16 | 16 | 16 | yes | x=0xFFFF: 16 ones |
| 7 | RCX=51966 | 0 | 0 | 0 | yes | x=0xCAFE: low bit 0 |
| 8 | RCX=51967 | 8 | 8 | 8 | yes | x=0xCAFF: 8 trailing ones |
| 9 | RCX=3405691583 | 6 | 6 | 6 | yes | x=0xCAFEBABF: 6 trailing ones |
| 10 | RCX=18446744073709551615 | 64 | 64 | 64 | yes | max u64: all 64 trailing ones |

## Source

```c
/* PC-state VM that counts the run length of trailing 1-bits on full
 * uint64_t.
 *   count = 0;
 *   while (state & 1) { count++; state >>= 1; }
 *   return count;
 * Variable trip 0..64.  Lift target: vm_trailingones64_loop_target.
 *
 * Distinct from vm_cttz64_loop (counts trailing ZEROS) and
 * vm_clz64_loop (leading zeros): counts trailing ONES via shift-loop.
 * No zero special case needed because state=0 has bit 0 = 0.
 */
#include <stdio.h>
#include <stdint.h>

enum ToVmPc {
    TO_LOAD       = 0,
    TO_LOOP_CHECK = 1,
    TO_LOOP_BODY  = 2,
    TO_HALT       = 3,
};

__declspec(noinline)
int vm_trailingones64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = TO_LOAD;

    while (1) {
        if (pc == TO_LOAD) {
            state = x;
            count = 0;
            pc = TO_LOOP_CHECK;
        } else if (pc == TO_LOOP_CHECK) {
            pc = ((state & 1ull) != 0ull) ? TO_LOOP_BODY : TO_HALT;
        } else if (pc == TO_LOOP_BODY) {
            count = count + 1;
            state = state >> 1;
            pc = TO_LOOP_CHECK;
        } else if (pc == TO_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_trailingones64(0xCAFF)=%d vm_trailingones64(max)=%d\n",
           vm_trailingones64_loop_target(0xCAFFull),
           vm_trailingones64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
