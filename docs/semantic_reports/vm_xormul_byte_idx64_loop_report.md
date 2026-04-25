# vm_xormul_byte_idx64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xormul_byte_idx64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xormul_byte_idx64_loop.ll`
- **Symbol:** `vm_xormul_byte_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xormul_byte_idx64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xormul_byte_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: byte0=1 *1 ^ byte1=0 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3 |
| 4 | RCX=7 | 7 | 7 | 7 | yes | x=7 n=8: only byte0=7 |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1 |
| 6 | RCX=3405691582 | 24 | 24 | 24 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 236 | 236 | 236 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: n=8 -> XOR of 0xFF*1..0xFF*8 cancels to 0 (sum of 1..8=36 even count) |
| 9 | RCX=72623859790382856 | 8 | 8 | 8 | yes | 0x0102...0708: n=1 byte0=8 (matches x=8) |
| 10 | RCX=1311768467463790320 | 240 | 240 | 240 | yes | 0x12345...EF0: n=1 byte0=0xF0 |

## Source

```c
/* PC-state VM that XORs scaled bytes into the accumulator across
 * n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFF) * (i + 1));   // unsigned byte * counter
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_xormul_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesmul_idx64_loop  (signed-byte sext + ADD accumulator)
 *   - vm_byteparity64_loop    (1-bit parity, no scaling)
 *   - vm_xorbytes64_loop      (XOR of bytes, no scaling)
 *
 * Tests unsigned byte (zext-i8) multiplied by dynamic counter (i+1)
 * folded into the accumulator via XOR rather than ADD.  The output
 * stays small for inputs whose bytes XOR to 0 after scaling (e.g.
 * all-0xFF cancels by symmetry of *1 ^ *2 ^ ... ^ *8 with same byte).
 */
#include <stdio.h>
#include <stdint.h>

enum XbVmPc {
    XB_INIT_ALL = 0,
    XB_CHECK    = 1,
    XB_BODY     = 2,
    XB_INC      = 3,
    XB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormul_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XB_INIT_ALL;

    while (1) {
        if (pc == XB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XB_CHECK;
        } else if (pc == XB_CHECK) {
            pc = (i < n) ? XB_BODY : XB_HALT;
        } else if (pc == XB_BODY) {
            r = r ^ ((s & 0xFFull) * (i + 1ull));
            s = s >> 8;
            pc = XB_INC;
        } else if (pc == XB_INC) {
            i = i + 1ull;
            pc = XB_CHECK;
        } else if (pc == XB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormul_byte_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormul_byte_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
```
