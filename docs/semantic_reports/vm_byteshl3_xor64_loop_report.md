# vm_byteshl3_xor64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_byteshl3_xor64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_byteshl3_xor64_loop.ll`
- **Symbol:** `vm_byteshl3_xor64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_byteshl3_xor64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_byteshl3_xor64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: 1 << 0 ^ 0=1 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3 |
| 4 | RCX=7 | 7 | 7 | 7 | yes | x=7 n=8: only byte0 |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1 |
| 6 | RCX=3405691582 | 110318 | 110318 | 110318 | yes | 0xCAFEBABE: n=7 - bytes XOR-stacked at 3-bit stride |
| 7 | RCX=3735928559 | 103007 | 103007 | 103007 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 476952263 | 476952263 | 476952263 | yes | all 0xFF n=8: 0xFF placed at 0,3,6,9,...,21 bit positions then XORed |
| 9 | RCX=72623859790382856 | 8 | 8 | 8 | yes | 0x0102...0708: n=1 byte0=8 |
| 10 | RCX=1311768467463790320 | 240 | 240 | 240 | yes | 0x12345...EF0: n=1 byte0=0xF0 |

## Source

```c
/* PC-state VM that XORs each byte shifted left by (i*3) bits into r:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFF) << (i * 3));   // dynamic shl by 3*i
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byteshl3_xor64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_pack64_loop  (dynamic shl by i directly, 2-bit chunks)
 *   - vm_byterev_window64_loop (constant shl-by-8 packing)
 *   - vm_xormul_byte_idx64_loop (byte * counter, no shift)
 *
 * Tests `shl i64 byte, %i*3` (dynamic shl by a NON-trivial counter
 * expression - mul-then-shl) inside dispatcher loop body.  Each
 * iter's byte lands at a different 3-bit-stride offset, so byte0
 * occupies bits 0-7, byte1 bits 3-10 (overlapping byte0's high), etc.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_INIT_ALL = 0,
    BS_CHECK    = 1,
    BS_BODY     = 2,
    BS_INC      = 3,
    BS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_byteshl3_xor64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BS_INIT_ALL;

    while (1) {
        if (pc == BS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BS_CHECK;
        } else if (pc == BS_CHECK) {
            pc = (i < n) ? BS_BODY : BS_HALT;
        } else if (pc == BS_BODY) {
            r = r ^ ((s & 0xFFull) << (i * 3ull));
            s = s >> 8;
            pc = BS_INC;
        } else if (pc == BS_INC) {
            i = i + 1ull;
            pc = BS_CHECK;
        } else if (pc == BS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byteshl3_xor64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byteshl3_xor64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
