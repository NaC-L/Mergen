# vm_divcount64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_divcount64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_divcount64_loop.ll`
- **Symbol:** `vm_divcount64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_divcount64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_divcount64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 63 | 63 | 63 | yes | x=0: ~x=max u64, div=2 -> 63 halvings |
| 2 | RCX=1 | 40 | 40 | 40 | yes | x=1: div=3, log_3(max-1) |
| 3 | RCX=2 | 31 | 31 | 31 | yes | x=2: div=4, log_4(max-2) |
| 4 | RCX=255 | 7 | 7 | 7 | yes | x=0xFF: div=257, log_257(max-255) |
| 5 | RCX=51966 | 7 | 7 | 7 | yes | x=0xCAFE: div=256 |
| 6 | RCX=3405691582 | 8 | 8 | 8 | yes | x=0xCAFEBABE: div=192 |
| 7 | RCX=1311768467463790320 | 8 | 8 | 8 | yes | x=0x123...DEF0: div=242 |
| 8 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | max u64: ~x=0 < div, count=0 |
| 9 | RCX=11400714819323198485 | 13 | 13 | 13 | yes | x=K: div=23, log_23 |
| 10 | RCX=3735928559 | 8 | 8 | 8 | yes | x=0xDEADBEEF: div=241 |

## Source

```c
/* PC-state VM that counts how many times an i64 state can be divided
 * by an input-derived divisor before it falls below the divisor.
 *   divisor = (x & 0xFF) + 2;   // 2..257, never zero
 *   state   = ~x;
 *   count   = 0;
 *   while (state >= divisor) { state /= divisor; count++; }
 *   return count;
 * Lift target: vm_divcount64_loop_target.
 *
 * Distinct from vm_gcd64_loop (urem-driven Euclidean): exercises
 * repeated i64 udiv inside a data-dependent loop (variable trip 0..63
 * depending on log_{divisor}(state)).
 */
#include <stdio.h>
#include <stdint.h>

enum DvVmPc {
    DV_LOAD       = 0,
    DV_LOOP_CHECK = 1,
    DV_LOOP_BODY  = 2,
    DV_HALT       = 3,
};

__declspec(noinline)
int vm_divcount64_loop_target(uint64_t x) {
    uint64_t divisor = 0;
    uint64_t state   = 0;
    int      count   = 0;
    int      pc      = DV_LOAD;

    while (1) {
        if (pc == DV_LOAD) {
            divisor = (x & 0xFFull) + 2ull;
            state   = ~x;
            count   = 0;
            pc = DV_LOOP_CHECK;
        } else if (pc == DV_LOOP_CHECK) {
            pc = (state >= divisor) ? DV_LOOP_BODY : DV_HALT;
        } else if (pc == DV_LOOP_BODY) {
            state = state / divisor;
            count = count + 1;
            pc = DV_LOOP_CHECK;
        } else if (pc == DV_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_divcount64(0)=%d vm_divcount64(0xCAFE)=%d\n",
           vm_divcount64_loop_target(0ull),
           vm_divcount64_loop_target(0xCAFEull));
    return 0;
}
```
