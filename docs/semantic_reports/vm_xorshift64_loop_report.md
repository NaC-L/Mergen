# vm_xorshift64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xorshift64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xorshift64_loop.ll`
- **Symbol:** `vm_xorshift64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xorshift64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xorshift64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1082269761 | 1082269761 | 1082269761 | yes | x=0: state init=1 |
| 2 | RCX=1 | 1152992998833853505 | 1152992998833853505 | 1152992998833853505 | yes | x=1, n=2 |
| 3 | RCX=7 | 11855148856360355748 | 11855148856360355748 | 11855148856360355748 | yes | x=7, n=8 max |
| 4 | RCX=255 | 16011667717177914820 | 16011667717177914820 | 16011667717177914820 | yes | x=0xFF, n=8 |
| 5 | RCX=51966 | 2924436104009635916 | 2924436104009635916 | 2924436104009635916 | yes | x=0xCAFE, n=7 |
| 6 | RCX=3405691582 | 13109524460698099542 | 13109524460698099542 | 13109524460698099542 | yes | x=0xCAFEBABE, n=7 |
| 7 | RCX=1311768467463790320 | 18338672410791262988 | 18338672410791262988 | 18338672410791262988 | yes | 0x123...DEF0, n=1 |
| 8 | RCX=18446744073709551615 | 16429531919753378102 | 16429531919753378102 | 16429531919753378102 | yes | max u64, n=8 |
| 9 | RCX=11400714819323198485 | 10885233071271705465 | 10885233071271705465 | 10885233071271705465 | yes | x=K (golden), n=6 |
| 10 | RCX=3735928559 | 7170143391515948286 | 7170143391515948286 | 7170143391515948286 | yes | x=0xDEADBEEF, n=8 |

## Source

```c
/* PC-state VM running Marsaglia's xorshift64 PRNG.
 *   state = x | 1;
 *   for i in 0..n: { state ^= state << 13; state ^= state >> 7; state ^= state << 17; }
 *   return state;
 * Variable trip n = (x & 7) + 1 (1..8).  Returns full uint64_t.
 * Lift target: vm_xorshift64_loop_target.
 *
 * Distinct from vm_lfsr64_loop (single-bit feedback) and vm_pcg64_loop
 * (LCG step + xor-shift output): exercises three sequential shift+xor
 * compound operations per loop iteration on full i64 state, with mixed
 * left-shift and right-shift directions.
 */
#include <stdio.h>
#include <stdint.h>

enum XsVmPc {
    XS_LOAD       = 0,
    XS_INIT       = 1,
    XS_LOOP_CHECK = 2,
    XS_LOOP_BODY  = 3,
    XS_LOOP_INC   = 4,
    XS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_xorshift64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = XS_LOAD;

    while (1) {
        if (pc == XS_LOAD) {
            state = x | 1ull;
            n     = (int)(x & 7ull) + 1;
            pc = XS_INIT;
        } else if (pc == XS_INIT) {
            idx = 0;
            pc = XS_LOOP_CHECK;
        } else if (pc == XS_LOOP_CHECK) {
            pc = (idx < n) ? XS_LOOP_BODY : XS_HALT;
        } else if (pc == XS_LOOP_BODY) {
            state = state ^ (state << 13);
            state = state ^ (state >> 7);
            state = state ^ (state << 17);
            pc = XS_LOOP_INC;
        } else if (pc == XS_LOOP_INC) {
            idx = idx + 1;
            pc = XS_LOOP_CHECK;
        } else if (pc == XS_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorshift64(0xCAFE)=%llu vm_xorshift64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xorshift64_loop_target(0xCAFEull),
           (unsigned long long)vm_xorshift64_loop_target(0xCAFEBABEull));
    return 0;
}
```
