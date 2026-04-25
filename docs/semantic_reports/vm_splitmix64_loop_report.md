# vm_splitmix64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_splitmix64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_splitmix64_loop.ll`
- **Symbol:** `vm_splitmix64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_splitmix64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_splitmix64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 16294208416658607535 | 16294208416658607535 | 16294208416658607535 | yes | x=0, n=1: first SplitMix64 output |
| 2 | RCX=1 | 13757245211066428519 | 13757245211066428519 | 13757245211066428519 | yes | x=1, n=2 |
| 3 | RCX=7 | 6051947643683389182 | 6051947643683389182 | 6051947643683389182 | yes | x=7, n=8 max |
| 4 | RCX=255 | 3595160614358814015 | 3595160614358814015 | 3595160614358814015 | yes | x=0xFF, n=8 |
| 5 | RCX=51966 | 18335744145558701823 | 18335744145558701823 | 18335744145558701823 | yes | x=0xCAFE, n=7 |
| 6 | RCX=3405691582 | 40956773586522747 | 40956773586522747 | 40956773586522747 | yes | x=0xCAFEBABE, n=7 |
| 7 | RCX=1311768467463790320 | 1592342178222199016 | 1592342178222199016 | 1592342178222199016 | yes | 0x123...DEF0, n=1 |
| 8 | RCX=18446744073709551615 | 4638043754431676516 | 4638043754431676516 | 4638043754431676516 | yes | max u64, n=8 |
| 9 | RCX=11400714819323198485 | 3207296026000306913 | 3207296026000306913 | 3207296026000306913 | yes | K (golden), n=6 |
| 10 | RCX=3735928559 | 12901208535622949722 | 12901208535622949722 | 12901208535622949722 | yes | 0xDEADBEEF, n=8 |

## Source

```c
/* PC-state VM running n iterations of the SplitMix64 PRNG.
 *   state = x;  z = 0;
 *   for i in 0..n:
 *     state += 0x9E3779B97F4A7C15
 *     z = state
 *     z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
 *     z = (z ^ (z >> 27)) * 0x94D049BB133111EB
 *     z = z ^ (z >> 31)
 *   return z;
 * Variable trip n = (x & 7) + 1.
 * Lift target: vm_splitmix64_loop_target.
 *
 * Distinct from vm_xorshift64_loop / vm_xs64star_loop / vm_pcg64_loop /
 * vm_fmix64_loop: SplitMix64 uses TWO multiplications (both by distinct
 * 64-bit primes) interleaved with three xor-with-shift steps inside a
 * loop body that also advances a 64-bit Weyl-style counter.
 */
#include <stdio.h>
#include <stdint.h>

enum SmVmPc {
    SMV_LOAD       = 0,
    SMV_INIT       = 1,
    SMV_LOOP_CHECK = 2,
    SMV_LOOP_BODY  = 3,
    SMV_LOOP_INC   = 4,
    SMV_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_splitmix64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    uint64_t z     = 0;
    int      pc    = SMV_LOAD;

    while (1) {
        if (pc == SMV_LOAD) {
            state = x;
            z     = 0ull;
            n     = (int)(x & 7ull) + 1;
            pc = SMV_INIT;
        } else if (pc == SMV_INIT) {
            idx = 0;
            pc = SMV_LOOP_CHECK;
        } else if (pc == SMV_LOOP_CHECK) {
            pc = (idx < n) ? SMV_LOOP_BODY : SMV_HALT;
        } else if (pc == SMV_LOOP_BODY) {
            state = state + 0x9E3779B97F4A7C15ull;
            z = state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
            z = z ^ (z >> 31);
            pc = SMV_LOOP_INC;
        } else if (pc == SMV_LOOP_INC) {
            idx = idx + 1;
            pc = SMV_LOOP_CHECK;
        } else if (pc == SMV_HALT) {
            return z;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_splitmix64(0xCAFE)=%llu vm_splitmix64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_splitmix64_loop_target(0xCAFEull),
           (unsigned long long)vm_splitmix64_loop_target(0xDEADBEEFull));
    return 0;
}
```
