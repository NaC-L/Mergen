# vm_ipow64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_ipow64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_ipow64_loop.ll`
- **Symbol:** `vm_ipow64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_ipow64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_ipow64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0, RDX=0 | 1 | 1 | 1 | yes | any^0=1 |
| 2 | RCX=2, RDX=10 | 59049 | 59049 | 59049 | yes | 3^10=59049 (base=x\|1) |
| 3 | RCX=3, RDX=7 | 2187 | 2187 | 2187 | yes | 3^7=2187 |
| 4 | RCX=5, RDX=15 | 30517578125 | 30517578125 | 30517578125 | yes | 5^15 (max exp) |
| 5 | RCX=51966, RDX=7 | 15893640546814037247 | 15893640546814037247 | 15893640546814037247 | yes | 0xCAFF^7 (wraps mod 2^64) |
| 6 | RCX=3405691582, RDX=5 | 12729405259367974335 | 12729405259367974335 | 12729405259367974335 | yes | 0xCAFEBABF^5 wraps |
| 7 | RCX=2, RDX=15 | 14348907 | 14348907 | 14348907 | yes | 3^15 |
| 8 | RCX=18446744073709551615, RDX=3 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | max u64 ^3 = max u64 (-1^3 = -1 mod 2^64) |
| 9 | RCX=1, RDX=15 | 1 | 1 | 1 | yes | 1^anything |
| 10 | RCX=11400714819323198485, RDX=4 | 15655466665053923249 | 15655466665053923249 | 15655466665053923249 | yes | K^4 |

## Source

```c
/* PC-state VM running i64 integer-power via square-and-multiply, no
 * modulo.
 *   result = 1; base = x | 1; exp = y & 0xF;
 *   while (exp) { if (exp & 1) result *= base; base *= base; exp >>= 1; }
 *   return result;     // (x|1)^(y&0xF) mod 2^64
 * Lift target: vm_ipow64_loop_target.
 *
 * Distinct from vm_powmod64_loop (urem inside body) and vm_factorial64_loop
 * (linear i*r): exercises i64 mul-only accumulation with conditional
 * gating by exp&1, plus parallel base squaring.
 */
#include <stdio.h>
#include <stdint.h>

enum IpVmPc {
    IP_LOAD       = 0,
    IP_LOOP_CHECK = 1,
    IP_LOOP_BODY  = 2,
    IP_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_ipow64_loop_target(uint64_t x, uint64_t y) {
    uint64_t result = 0;
    uint64_t base   = 0;
    uint64_t exp    = 0;
    int      pc     = IP_LOAD;

    while (1) {
        if (pc == IP_LOAD) {
            result = 1ull;
            base   = x | 1ull;
            exp    = y & 0xFull;
            pc = IP_LOOP_CHECK;
        } else if (pc == IP_LOOP_CHECK) {
            pc = (exp != 0ull) ? IP_LOOP_BODY : IP_HALT;
        } else if (pc == IP_LOOP_BODY) {
            if ((exp & 1ull) != 0ull) {
                result = result * base;
            }
            base = base * base;
            exp = exp >> 1;
            pc = IP_LOOP_CHECK;
        } else if (pc == IP_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_ipow64(2,10)=%llu vm_ipow64(0xCAFE,7)=%llu\n",
           (unsigned long long)vm_ipow64_loop_target(2ull, 10ull),
           (unsigned long long)vm_ipow64_loop_target(0xCAFEull, 7ull));
    return 0;
}
```
