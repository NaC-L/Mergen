# vm_byteshl_data64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_byteshl_data64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_byteshl_data64_loop.ll`
- **Symbol:** `vm_byteshl_data64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_byteshl_data64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_byteshl_data64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 0 | 0 | 0 | yes | x=1 n=2: byte0=1 (b&7=1, b>>4=0); byte1=0 |
| 3 | RCX=2 | 0 | 0 | 0 | yes | x=2 n=3 |
| 4 | RCX=7 | 0 | 0 | 0 | yes | x=7 n=8: byte0=7 produces shl by 7 of 0=0 |
| 5 | RCX=8 | 0 | 0 | 0 | yes | x=8 n=1: shl by 0=0; OR byte>>4=0 |
| 6 | RCX=3405691582 | 12092 | 12092 | 12092 | yes | 0xCAFEBABE: n=7 data-driven shifts |
| 7 | RCX=3735928559 | 1858189 | 1858189 | 1858189 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 8510739453298575 | 8510739453298575 | 8510739453298575 | yes | all 0xFF: shl by 7 each iter combined with OR 0xF |
| 9 | RCX=72623859790382856 | 0 | 0 | 0 | yes | 0x0102...0708: n=1 byte0=8 |
| 10 | RCX=1311768467463790320 | 15 | 15 | 15 | yes | 0x12345...EF0: n=1 byte0=0xF0 -> shl by 0=0, OR 0xF=15 |

## Source

```c
/* PC-state VM with DATA-DEPENDENT shift amount inside the loop body:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = (r << (b & 7)) | (b >> 4);   // shl amount comes from byte data
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byteshl_data64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_pack64_loop      (shl by loop index i)
 *   - vm_byteshl3_xor64_loop     (shl by i*3 - counter expression)
 *   - vm_bitfetch_window64_loop  (lshr by counter)
 *
 * Tests `shl i64 r, %byte_amount` where the shift amount is derived
 * from the BYTE STREAM rather than the loop counter.  Each iter's
 * amount is bounded to 0..7 by `& 7` so undefined-shift behavior is
 * avoided.  Combined with OR of the byte's high nibble.
 */
#include <stdio.h>
#include <stdint.h>

enum BdVmPc {
    BD_INIT_ALL = 0,
    BD_CHECK    = 1,
    BD_BODY     = 2,
    BD_INC      = 3,
    BD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_byteshl_data64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BD_INIT_ALL;

    while (1) {
        if (pc == BD_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BD_CHECK;
        } else if (pc == BD_CHECK) {
            pc = (i < n) ? BD_BODY : BD_HALT;
        } else if (pc == BD_BODY) {
            uint64_t b = s & 0xFFull;
            r = (r << (b & 7ull)) | (b >> 4);
            s = s >> 8;
            pc = BD_INC;
        } else if (pc == BD_INC) {
            i = i + 1ull;
            pc = BD_CHECK;
        } else if (pc == BD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byteshl_data64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_byteshl_data64_loop_target(0xDEADBEEFull));
    return 0;
}
```
