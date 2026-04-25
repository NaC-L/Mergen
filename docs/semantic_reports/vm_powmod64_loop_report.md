# vm_powmod64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_powmod64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_powmod64_loop.ll`
- **Symbol:** `vm_powmod64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_powmod64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_powmod64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=2, RDX=10, R8=1000 | 24 | 24 | 24 | yes | 2^10 mod 1000 = 24 |
| 2 | RCX=3, RDX=7, R8=100 | 87 | 87 | 87 | yes | 3^7 mod 100 = 87 |
| 3 | RCX=2, RDX=32, R8=4294967296 | 0 | 0 | 0 | yes | 2^32 mod 2^32 = 0 |
| 4 | RCX=2, RDX=64, R8=17 | 1 | 1 | 1 | yes | 2^64 mod 17 = 1 (Fermat) |
| 5 | RCX=51966, RDX=47806, R8=57005 | 1091 | 1091 | 1091 | yes | 0xCAFE^0xBABE mod 0xDEAD |
| 6 | RCX=18446744073709551615, RDX=2, R8=18446744073709551615 | 1 | 1 | 1 | yes | max^2 mod max = 1 |
| 7 | RCX=7, RDX=0, R8=13 | 1 | 1 | 1 | yes | x^0 = 1 |
| 8 | RCX=1, RDX=9223372036854775808, R8=1152921504606846976 | 1 | 1 | 1 | yes | 1^anything = 1 |
| 9 | RCX=11400714819323198485, RDX=100, R8=4294967297 | 2730760 | 2730760 | 2730760 | yes | K^100 mod (2^32+1) |
| 10 | RCX=123456789, RDX=1000000007, R8=998244353 | 903711187 | 903711187 | 903711187 | yes | large primes-ish |

## Source

```c
/* PC-state VM running fast modular exponentiation on uint64_t.
 *   r = 1 % mod
 *   while (exp) {
 *     if (exp & 1) r = (r * base) % mod;
 *     base = (base * base) % mod;
 *     exp >>= 1;
 *   }
 *   return r;
 * Inputs: base in RCX, exp in RDX, mod in R8.  All full uint64_t.
 * Lift target: vm_powmod64_loop_target.
 *
 * Distinct from vm_powermod_loop (i32 powmod): exercises i64 mul +
 * i64 urem inside a variable-trip loop (trip = bit length of exp).
 */
#include <stdio.h>
#include <stdint.h>

enum PmVmPc {
    PM_LOAD       = 0,
    PM_INIT       = 1,
    PM_LOOP_CHECK = 2,
    PM_LOOP_BODY  = 3,
    PM_HALT       = 4,
};

__declspec(noinline)
uint64_t vm_powmod64_loop_target(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t b   = 0;
    uint64_t e   = 0;
    uint64_t m   = 0;
    uint64_t r   = 0;
    int      pc  = PM_LOAD;

    while (1) {
        if (pc == PM_LOAD) {
            b = base;
            e = exp;
            m = mod;
            pc = PM_INIT;
        } else if (pc == PM_INIT) {
            r = 1ull % m;
            pc = PM_LOOP_CHECK;
        } else if (pc == PM_LOOP_CHECK) {
            pc = (e != 0ull) ? PM_LOOP_BODY : PM_HALT;
        } else if (pc == PM_LOOP_BODY) {
            if ((e & 1ull) != 0ull) {
                r = (r * b) % m;
            }
            b = (b * b) % m;
            e = e >> 1;
            pc = PM_LOOP_CHECK;
        } else if (pc == PM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_powmod64(2,10,1000)=%llu vm_powmod64(3,7,100)=%llu\n",
           (unsigned long long)vm_powmod64_loop_target(2ull, 10ull, 1000ull),
           (unsigned long long)vm_powmod64_loop_target(3ull, 7ull, 100ull));
    return 0;
}
```
