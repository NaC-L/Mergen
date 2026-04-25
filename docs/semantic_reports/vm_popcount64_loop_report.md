# vm_popcount64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_popcount64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_popcount64_loop.ll`
- **Symbol:** `vm_popcount64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_popcount64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_popcount64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: trip count 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 |
| 3 | RCX=7 | 3 | 3 | 3 | yes | x=7: 3 bits |
| 4 | RCX=18446744073709551615 | 64 | 64 | 64 | yes | max u64: max trip count |
| 5 | RCX=9223372036854775808 | 1 | 1 | 1 | yes | x=2^63: single high bit |
| 6 | RCX=3405691582 | 22 | 22 | 22 | yes | 0xCAFEBABE |
| 7 | RCX=1311768467463790320 | 32 | 32 | 32 | yes | 0x123456789ABCDEF0 |
| 8 | RCX=12297829382473034410 | 32 | 32 | 32 | yes | 0xAAAA...: alternating high |
| 9 | RCX=6148914691236517205 | 32 | 32 | 32 | yes | 0x5555...: alternating low |
| 10 | RCX=11400714819323198485 | 38 | 38 | 38 | yes | x=K (golden ratio) |

## Source

```c
/* PC-state VM running Brian Kernighan's popcount on a FULL uint64_t.
 *   while (x) { x &= (x - 1); count++; }
 * Trip count = popcount(x), bounded 0..64.  Returns count as int.
 * Lift target: vm_popcount64_loop_target.
 *
 * Distinct from vm_kernighan_loop (i32 popcount) and vm_popcount_loop
 * (different style): exercises the same shape on full 64-bit state with
 * an input-derived variable trip count up to 64.
 */
#include <stdio.h>
#include <stdint.h>

enum P64VmPc {
    P64_LOAD       = 0,
    P64_LOOP_CHECK = 1,
    P64_LOOP_BODY  = 2,
    P64_HALT       = 3,
};

__declspec(noinline)
int vm_popcount64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = P64_LOAD;

    while (1) {
        if (pc == P64_LOAD) {
            state = x;
            count = 0;
            pc = P64_LOOP_CHECK;
        } else if (pc == P64_LOOP_CHECK) {
            pc = (state != 0ull) ? P64_LOOP_BODY : P64_HALT;
        } else if (pc == P64_LOOP_BODY) {
            state = state & (state - 1ull);
            count = count + 1;
            pc = P64_LOOP_CHECK;
        } else if (pc == P64_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_popcount64(0xCAFEBABE)=%d vm_popcount64(0xFFFFFFFFFFFFFFFF)=%d\n",
           vm_popcount64_loop_target(0xCAFEBABEull),
           vm_popcount64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
