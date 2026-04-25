# vm_peasant64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_peasant64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_peasant64_loop.ll`
- **Symbol:** `vm_peasant64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_peasant64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_peasant64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0, RDX=0 | 0 | 0 | 0 | yes | 0*0=0: skip loop |
| 2 | RCX=3, RDX=5 | 15 | 15 | 15 | yes | 3*5=15 |
| 3 | RCX=11, RDX=13 | 143 | 143 | 143 | yes | 11*13=143 |
| 4 | RCX=51966, RDX=47806 | 2484286596 | 2484286596 | 2484286596 | yes | 0xCAFE*0xBABE |
| 5 | RCX=3405691582, RDX=3735928559 | 12723420444339690338 | 12723420444339690338 | 12723420444339690338 | yes | 0xCAFEBABE * 0xDEADBEEF (wraps mod 2^64) |
| 6 | RCX=9223372036854775808, RDX=2 | 0 | 0 | 0 | yes | 2^63*2=2^64 wraps to 0 |
| 7 | RCX=18446744073709551615, RDX=18446744073709551615 | 1 | 1 | 1 | yes | max u64 * max u64 = 1 mod 2^64 |
| 8 | RCX=7, RDX=0 | 0 | 0 | 0 | yes | y=0: skip loop |
| 9 | RCX=0, RDX=7 | 0 | 0 | 0 | yes | x=0: a=0, no contribution |
| 10 | RCX=4294967297, RDX=4294967297 | 8589934593 | 8589934593 | 8589934593 | yes | (2^32+1)*(2^32+1) wraps mod 2^64 |

## Source

```c
/* PC-state VM running Russian-peasant (shift-and-add) multiplication
 * on full uint64_t.
 *   r = 0; a = x; b = y;
 *   while (b) { if (b & 1) r += a; a <<= 1; b >>= 1; }
 *   return r;     // (a*b) mod 2^64
 * Variable trip = bit length of b (1..64).  Inputs in RCX, RDX.
 * Lift target: vm_peasant64_loop_target.
 *
 * Distinct from existing i64 mul samples (vm_dual_i64_loop / vm_pcg64_loop):
 * exercises explicit shift-and-add multiply with conditional accumulate
 * inside a data-dependent loop, rather than direct mul i64.
 */
#include <stdio.h>
#include <stdint.h>

enum PvVmPc {
    PV_LOAD       = 0,
    PV_LOOP_CHECK = 1,
    PV_LOOP_BODY  = 2,
    PV_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_peasant64_loop_target(uint64_t x, uint64_t y) {
    uint64_t a = 0;
    uint64_t b = 0;
    uint64_t r = 0;
    int      pc = PV_LOAD;

    while (1) {
        if (pc == PV_LOAD) {
            a = x;
            b = y;
            r = 0ull;
            pc = PV_LOOP_CHECK;
        } else if (pc == PV_LOOP_CHECK) {
            pc = (b != 0ull) ? PV_LOOP_BODY : PV_HALT;
        } else if (pc == PV_LOOP_BODY) {
            if ((b & 1ull) != 0ull) {
                r = r + a;
            }
            a = a << 1;
            b = b >> 1;
            pc = PV_LOOP_CHECK;
        } else if (pc == PV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_peasant64(11,13)=%llu vm_peasant64(0xCAFE,0xBABE)=%llu\n",
           (unsigned long long)vm_peasant64_loop_target(11ull, 13ull),
           (unsigned long long)vm_peasant64_loop_target(0xCAFEull, 0xBABEull));
    return 0;
}
```
