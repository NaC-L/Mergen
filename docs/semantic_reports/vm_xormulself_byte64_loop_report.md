# vm_xormulself_byte64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_xormulself_byte64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_xormulself_byte64_loop.ll`
- **Symbol:** `vm_xormulself_byte64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_xormulself_byte64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_xormulself_byte64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: 0^(1*1)=1; 1^(0*2)=1 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3 |
| 4 | RCX=7 | 7 | 7 | 7 | yes | x=7 n=8: only byte0=7 contributes |
| 5 | RCX=8 | 8 | 8 | 8 | yes | x=8 n=1: 0^(8*1)=8 |
| 6 | RCX=3405691582 | 1818216336 | 1818216336 | 1818216336 | yes | 0xCAFEBABE: n=7 self-referential cascade |
| 7 | RCX=3735928559 | 1746890527 | 1746890527 | 1746890527 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | all 0xFF: cascades but ends at all-1s |
| 9 | RCX=72623859790382856 | 8 | 8 | 8 | yes | 0x0102...0708: n=1 byte=8 |
| 10 | RCX=1311768467463790320 | 240 | 240 | 240 | yes | 0x12345...EF0: n=1 byte=0xF0 |

## Source

```c
/* PC-state VM with self-referential multiply per iter:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = r ^ (b * (r + 1));   // r appears in mul operand
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_xormulself_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_byte_idx64_loop  (byte * counter, XOR-folded)
 *   - vm_bytesmul_idx64_loop     (sext byte * counter, ADD)
 *   - vm_squareadd64_loop        (r*r self-multiply on full state)
 *
 * Tests `mul i64 byte, (r+1)` where the multiplier operand is the
 * accumulator+1 (self-reference).  Each iter the byte scales an
 * incremented snapshot of r and XORs back.  Reaches 200-sample
 * milestone.
 */
#include <stdio.h>
#include <stdint.h>

enum XmVmPc {
    XM_INIT_ALL = 0,
    XM_CHECK    = 1,
    XM_BODY     = 2,
    XM_INC      = 3,
    XM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormulself_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XM_INIT_ALL;

    while (1) {
        if (pc == XM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XM_CHECK;
        } else if (pc == XM_CHECK) {
            pc = (i < n) ? XM_BODY : XM_HALT;
        } else if (pc == XM_BODY) {
            uint64_t b = s & 0xFFull;
            r = r ^ (b * (r + 1ull));
            s = s >> 8;
            pc = XM_INC;
        } else if (pc == XM_INC) {
            i = i + 1ull;
            pc = XM_CHECK;
        } else if (pc == XM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormulself_byte64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormulself_byte64_loop_target(0xCAFEBABEull));
    return 0;
}
```
