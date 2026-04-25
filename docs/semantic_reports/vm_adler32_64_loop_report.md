# vm_adler32_64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_adler32_64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_adler32_64_loop.ll`
- **Symbol:** `vm_adler32_64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_adler32_64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_adler32_64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 65537 | 65537 | 65537 | yes | x=0 n=1: a=1 b=1 -> (1<<16)\|1 |
| 2 | RCX=1 | 262146 | 262146 | 262146 | yes | x=1 n=2: bytes [1,0] |
| 3 | RCX=2 | 589827 | 589827 | 589827 | yes | x=2 n=3 |
| 4 | RCX=7 | 4194312 | 4194312 | 4194312 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 589833 | 589833 | 589833 | yes | x=8 n=1: byte 0x08 alone |
| 6 | RCX=3405691582 | 296944449 | 296944449 | 296944449 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 353764153 | 353764153 | 353764153 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 602146809 | 602146809 | 602146809 | yes | all 0xFF: 8 max bytes |
| 9 | RCX=1311768467463790320 | 15794417 | 15794417 | 15794417 | yes | 0x12345...EF0: n=1 byte 0xF0 |
| 10 | RCX=72623859790382856 | 589833 | 589833 | 589833 | yes | 0x0102...0708: n=1 byte 0x08 (matches x=8) |

## Source

```c
/* PC-state VM that runs an Adler-32-style two-accumulator modular hash
 * over n = (x & 7) + 1 bytes consumed from the input register:
 *
 *   n = (x & 7) + 1;
 *   s = x; a = 1; b = 0;
 *   for (i = 0; i < n; i++) {
 *     a = (a + (s & 0xFF)) % 65521;     // ADLER prime
 *     b = (b + a)         % 65521;
 *     s >>= 8;
 *   }
 *   return (b << 16) | a;
 *
 * Lift target: vm_adler32_64_loop_target.
 *
 * Distinct from:
 *   - vm_fnv1a64_loop  (single state, multiplicative)
 *   - vm_djb264_loop   (single additive multiplier)
 *   - vm_byterange64_loop (two reductions but no modular arithmetic)
 *
 * Two PARALLEL additive accumulators where b feeds on the running a.
 * Each modular step exercises i64 urem by 65521 (a non-power-of-2
 * prime) which the lifter must lower via magic-number division.
 * The result packs both accumulators into one i64 via shl-or.
 */
#include <stdio.h>
#include <stdint.h>

enum AdVmPc {
    AD_INIT_ALL = 0,
    AD_CHECK    = 1,
    AD_STEP_A   = 2,
    AD_STEP_B   = 3,
    AD_SHIFT    = 4,
    AD_INC      = 5,
    AD_HALT     = 6,
};

__declspec(noinline)
uint64_t vm_adler32_64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t i  = 0;
    int      pc = AD_INIT_ALL;

    while (1) {
        if (pc == AD_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            a = 1ull;
            b = 0ull;
            i = 0ull;
            pc = AD_CHECK;
        } else if (pc == AD_CHECK) {
            pc = (i < n) ? AD_STEP_A : AD_HALT;
        } else if (pc == AD_STEP_A) {
            a = (a + (s & 0xFFull)) % 65521ull;
            pc = AD_STEP_B;
        } else if (pc == AD_STEP_B) {
            b = (b + a) % 65521ull;
            pc = AD_SHIFT;
        } else if (pc == AD_SHIFT) {
            s = s >> 8;
            pc = AD_INC;
        } else if (pc == AD_INC) {
            i = i + 1ull;
            pc = AD_CHECK;
        } else if (pc == AD_HALT) {
            return (b << 16) | a;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_adler32_64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_adler32_64_loop_target(0xCAFEBABEull));
    return 0;
}
```
