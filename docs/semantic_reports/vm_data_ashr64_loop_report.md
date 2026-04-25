# vm_data_ashr64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_data_ashr64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_data_ashr64_loop.ll`
- **Symbol:** `vm_data_ashr64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_data_ashr64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_data_ashr64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 n=1: r=0; (0 >> 0) + 0 = 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3 |
| 4 | RCX=7 | 7 | 7 | 7 | yes | x=7 n=8: only byte0=7 contributes |
| 5 | RCX=8 | 16 | 16 | 16 | yes | x=8 n=1: 8 ashr 0 + 8 = 16 |
| 6 | RCX=3405691582 | 52233 | 52233 | 52233 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 447 | 447 | 447 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 257 | 257 | 257 | yes | all 0xFF: ashr fills 1s -> stable -1 + 0xFF, several iters |
| 9 | RCX=9223372036854775808 | 9223372036854775808 | 9223372036854775808 | 9223372036854775808 | yes | x=2^63 n=1: ashr by 0=identity, +0=2^63 |
| 10 | RCX=1311768467463790320 | 1311768467463790560 | 1311768467463790560 | 1311768467463790560 | yes | 0x12345...EF0: n=1 byte=0xF0=240; ashr 0; +240 |

## Source

```c
/* PC-state VM with DATA-DEPENDENT arithmetic right-shift amount:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     int amt = (int)(b & 7);
 *     r = (uint64_t)((int64_t)r >> amt) + b;   // ashr by byte amount
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_data_ashr64_loop_target.
 *
 * Distinct from:
 *   - vm_byteshl_data64_loop  (data-dependent SHL)
 *   - vm_data_lshr64_loop     (data-dependent LSHR)
 *   - vm_dyn_ashr64_loop      (ashr by loop counter, NOT byte data)
 *
 * Completes the data-dependent shift trio (shl / lshr / ashr).
 * Sign-extending right-shift by an amount that comes from the byte
 * stream propagates the high bit of the running r through iterations,
 * producing different fills than lshr for high-bit-set states.
 */
#include <stdio.h>
#include <stdint.h>

enum DaVmPc {
    DA_INIT_ALL = 0,
    DA_CHECK    = 1,
    DA_BODY     = 2,
    DA_INC      = 3,
    DA_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_data_ashr64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DA_INIT_ALL;

    while (1) {
        if (pc == DA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DA_CHECK;
        } else if (pc == DA_CHECK) {
            pc = (i < n) ? DA_BODY : DA_HALT;
        } else if (pc == DA_BODY) {
            uint64_t b   = s & 0xFFull;
            int      amt = (int)(b & 7ull);
            r = (uint64_t)((int64_t)r >> amt) + b;
            s = s >> 8;
            pc = DA_INC;
        } else if (pc == DA_INC) {
            i = i + 1ull;
            pc = DA_CHECK;
        } else if (pc == DA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_data_ashr64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_data_ashr64_loop_target(0xDEADBEEFull));
    return 0;
}
```
