# vm_gcd64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_gcd64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_gcd64_loop.ll`
- **Symbol:** `vm_gcd64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_gcd64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_gcd64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0, RDX=0 | 0 | 0 | 0 | yes | both zero |
| 2 | RCX=12, RDX=18 | 6 | 6 | 6 | yes | gcd(12,18)=6 |
| 3 | RCX=0, RDX=7 | 7 | 7 | 7 | yes | gcd(0,7)=7 |
| 4 | RCX=7, RDX=0 | 7 | 7 | 7 | yes | gcd(7,0)=7: skip loop |
| 5 | RCX=9223372036854775808, RDX=4611686018427387904 | 4611686018427387904 | 4611686018427387904 | 4611686018427387904 | yes | gcd(2^63, 2^62)=2^62 |
| 6 | RCX=3405691582, RDX=3735928559 | 1 | 1 | 1 | yes | gcd(0xCAFEBABE, 0xDEADBEEF)=1 |
| 7 | RCX=18446744073709551615, RDX=18446744073709551614 | 1 | 1 | 1 | yes | adjacent max u64: coprime |
| 8 | RCX=123456789012345, RDX=987654321098765 | 5 | 5 | 5 | yes | large coprime-ish |
| 9 | RCX=51966, RDX=47806 | 2 | 2 | 2 | yes | gcd(0xCAFE, 0xBABE)=2 |
| 10 | RCX=18446744073709551614, RDX=2 | 2 | 2 | 2 | yes | gcd(max-1, 2)=2 |

## Source

```c
/* PC-state VM running the Euclidean GCD on full uint64_t values.
 *   while (b) { t = b; b = a % b; a = t; }
 *   return a;
 * Inputs: a in RCX, b in RDX (both full 64-bit).
 * Lift target: vm_gcd64_loop_target.
 *
 * Distinct from vm_gcd_loop (i32 GCD): exercises i64 urem in a
 * data-dependent loop with both operands at full width.
 */
#include <stdio.h>
#include <stdint.h>

enum G64VmPc {
    G64_LOAD       = 0,
    G64_LOOP_CHECK = 1,
    G64_LOOP_BODY  = 2,
    G64_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_gcd64_loop_target(uint64_t x, uint64_t y) {
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t t  = 0;
    int      pc = G64_LOAD;

    while (1) {
        if (pc == G64_LOAD) {
            a = x;
            b = y;
            pc = G64_LOOP_CHECK;
        } else if (pc == G64_LOOP_CHECK) {
            pc = (b != 0ull) ? G64_LOOP_BODY : G64_HALT;
        } else if (pc == G64_LOOP_BODY) {
            t = b;
            b = a % b;
            a = t;
            pc = G64_LOOP_CHECK;
        } else if (pc == G64_HALT) {
            return a;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_gcd64(12,18)=%llu vm_gcd64(0xCAFEBABE,0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_gcd64_loop_target(12ull, 18ull),
           (unsigned long long)vm_gcd64_loop_target(0xCAFEBABEull, 0xDEADBEEFull));
    return 0;
}
```
