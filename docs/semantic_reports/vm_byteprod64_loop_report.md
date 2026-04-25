# vm_byteprod64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_byteprod64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_byteprod64_loop.ll`
- **Symbol:** `vm_byteprod64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_byteprod64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_byteprod64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 n=1: 1*0=0 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | x=1 n=2: 1*1=1; 1*0=0 |
| 3 | RCX=2 | 0 | 0 | 0 | yes | x=2 n=3: byte0=2 then 0,0 -> 0 |
| 4 | RCX=7 | 0 | 0 | 0 | yes | x=7 n=8: only byte0=7 nonzero, then 0 |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1: 1*8=8 (no zero byte to wreck) |
| 6 | RCX=3405691582 | 0 | 0 | 0 | yes | 0xCAFEBABE: n=7 high bytes are 0 |
| 7 | RCX=3735928559 | 0 | 0 | 0 | yes | 0xDEADBEEF: n=8 high bytes are 0 |
| 8 | RCX=18446744073709551615 | 17878103347812890625 | 17878103347812890625 | 17878103347812890625 | yes | all 0xFF: 0xFF^8 mod 2^64 |
| 9 | RCX=72623859790382856 | 8 | 8 | 8 | yes | 0x0102...0708: n=1 byte0=8 |
| 10 | RCX=144965140780024580 | 1512 | 1512 | 1512 | yes | 0x0203...0304: n=5 -> 4*3*2*9*7=1512 |

## Source

```c
/* PC-state VM that computes the running product of bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 1;
 *   for (i = 0; i < n; i++) {
 *     r = r * (s & 0xFF);     // u8 multiplicative chain (mod 2^64)
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byteprod64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesq_sum64_loop          (per-byte squared, ADD-folded)
 *   - vm_xormul_byte_idx64_loop     (byte * counter, XOR-folded)
 *   - vm_uintadd_byte_idx64_loop    (byte * counter, ADD-folded)
 *   - vm_bytesmul_idx64_loop        (signed byte * counter, ADD-folded)
 *
 * Tests `mul i64 r, byte` chained across iterations.  Any zero byte
 * collapses the product to 0 for the rest of the loop, which the
 * lifter must not optimize away (the loop still runs to completion).
 * Inputs with no zero bytes propagate a meaningful product.
 */
#include <stdio.h>
#include <stdint.h>

enum BpVmPc {
    BP_INIT_ALL = 0,
    BP_CHECK    = 1,
    BP_BODY     = 2,
    BP_INC      = 3,
    BP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_byteprod64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BP_INIT_ALL;

    while (1) {
        if (pc == BP_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 1ull;
            i = 0ull;
            pc = BP_CHECK;
        } else if (pc == BP_CHECK) {
            pc = (i < n) ? BP_BODY : BP_HALT;
        } else if (pc == BP_BODY) {
            r = r * (s & 0xFFull);
            s = s >> 8;
            pc = BP_INC;
        } else if (pc == BP_INC) {
            i = i + 1ull;
            pc = BP_CHECK;
        } else if (pc == BP_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byteprod64(0x0203050709020304)=%llu\n",
           (unsigned long long)vm_byteprod64_loop_target(0x0203050709020304ull));
    return 0;
}
```
