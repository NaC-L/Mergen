# vm_revdecimal64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_revdecimal64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_revdecimal64_loop.ll`
- **Symbol:** `vm_revdecimal64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_revdecimal64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_revdecimal64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: skip loop |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 |
| 3 | RCX=10 | 1 | 1 | 1 | yes | x=10 -> 1 (trailing zero stripped) |
| 4 | RCX=100 | 1 | 1 | 1 | yes | x=100 -> 1 |
| 5 | RCX=123 | 321 | 321 | 321 | yes | x=123 -> 321 |
| 6 | RCX=12345 | 54321 | 54321 | 54321 | yes | x=12345 -> 54321 |
| 7 | RCX=1000000000 | 1 | 1 | 1 | yes | x=10^9 -> 1 |
| 8 | RCX=1234567890 | 987654321 | 987654321 | 987654321 | yes | x=1234567890 -> 987654321 |
| 9 | RCX=18446744073709551615 | 14722102589625661249 | 14722102589625661249 | 14722102589625661249 | yes | max u64 reversed (wraps) |
| 10 | RCX=11400714819323198485 | 3148900170713045563 | 3148900170713045563 | 3148900170713045563 | yes | K (golden) reversed (wraps) |

## Source

```c
/* PC-state VM that reverses the decimal digits of x.
 *   r = 0; s = x;
 *   while (s) { r = r * 10 + (s % 10); s /= 10; }
 *   return r;
 * Variable trip = number of decimal digits.  Returns full uint64_t
 * (very large inputs reverse to wraparound values).
 * Lift target: vm_revdecimal64_loop_target.
 *
 * Distinct from vm_digitprod64_loop (multiplies digits) and
 * vm_decdigits64_loop (counts digits): per-iter mul-by-10 + add-mod-10
 * + div-by-10 chain that reconstructs the reversed number digit by
 * digit.  Tests three i64 ops (mul, urem, udiv) against constant 10
 * inside the same loop body.
 */
#include <stdio.h>
#include <stdint.h>

enum RvVmPc {
    RV_LOAD       = 0,
    RV_LOOP_CHECK = 1,
    RV_LOOP_BODY  = 2,
    RV_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_revdecimal64_loop_target(uint64_t x) {
    uint64_t s = 0;
    uint64_t r = 0;
    int      pc = RV_LOAD;

    while (1) {
        if (pc == RV_LOAD) {
            s = x;
            r = 0ull;
            pc = RV_LOOP_CHECK;
        } else if (pc == RV_LOOP_CHECK) {
            pc = (s != 0ull) ? RV_LOOP_BODY : RV_HALT;
        } else if (pc == RV_LOOP_BODY) {
            r = r * 10ull + (s % 10ull);
            s = s / 10ull;
            pc = RV_LOOP_CHECK;
        } else if (pc == RV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_revdecimal64(12345)=%llu vm_revdecimal64(1234567890)=%llu\n",
           (unsigned long long)vm_revdecimal64_loop_target(12345ull),
           (unsigned long long)vm_revdecimal64_loop_target(1234567890ull));
    return 0;
}
```
