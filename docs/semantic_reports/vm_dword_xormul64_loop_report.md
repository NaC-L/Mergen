# vm_dword_xormul64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dword_xormul64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_dword_xormul64_loop.ll`
- **Symbol:** `vm_dword_xormul64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dword_xormul64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dword_xormul64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 2654435769 | 2654435769 | 2654435769 | yes | x=1 n=2: 1*GR^0=GR |
| 3 | RCX=2 | 5308871538 | 5308871538 | 5308871538 | yes | x=2 n=1 |
| 4 | RCX=3 | 7963307307 | 7963307307 | 7963307307 | yes | x=3 n=2: dword 3 then 0 |
| 5 | RCX=3405691582 | 9040189553442996558 | 9040189553442996558 | 9040189553442996558 | yes | 0xCAFEBABE: n=1 single dword |
| 6 | RCX=3735928559 | 9916782397438226871 | 9916782397438226871 | 9916782397438226871 | yes | 0xDEADBEEF: n=2 dword + 0 |
| 7 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: 2 XOR of 0xFFFFFFFF*GR cancel |
| 8 | RCX=72623859790382856 | 223718755872922824 | 223718755872922824 | 223718755872922824 | yes | 0x0102...0708: n=1 lower dword=0x05060708 |
| 9 | RCX=1311768467463790320 | 6891098688453380976 | 6891098688453380976 | 6891098688453380976 | yes | 0x12345...EF0: n=1 lower dword=0x9ABCDEF0 |
| 10 | RCX=18364758544493064720 | 5269663737911033232 | 5269663737911033232 | 5269663737911033232 | yes | 0xFEDCBA9876543210: n=1 lower dword=0x76543210 |

## Source

```c
/* PC-state VM that processes u32 dwords per iteration:
 *
 *   n = (x & 1) + 1;     // 1..2 dword iters
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     r = r ^ (d * 0x9E3779B9);   // golden-ratio prime mul
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_xormul64_loop_target.
 *
 * Distinct from:
 *   - vm_word_xormul64_loop  (u16 word stride)
 *   - vm_quad_byte_xor64_loop (4 BYTES per iter)
 *   - vm_xormuladd_chain64_loop (xor + mul + add, no stride)
 *
 * Tests u32 zext-i32 reads (mask 0xFFFFFFFF) multiplied by the
 * 32-bit golden-ratio prime 0x9E3779B9 and XOR-folded into the
 * accumulator.  Stride is 32 bits per iter; loop runs 1..2 times.
 */
#include <stdio.h>
#include <stdint.h>

enum DwVmPc {
    DW_INIT_ALL = 0,
    DW_CHECK    = 1,
    DW_BODY     = 2,
    DW_INC      = 3,
    DW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dword_xormul64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DW_INIT_ALL;

    while (1) {
        if (pc == DW_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DW_CHECK;
        } else if (pc == DW_CHECK) {
            pc = (i < n) ? DW_BODY : DW_HALT;
        } else if (pc == DW_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            r = r ^ (d * 0x9E3779B9ull);
            s = s >> 32;
            pc = DW_INC;
        } else if (pc == DW_INC) {
            i = i + 1ull;
            pc = DW_CHECK;
        } else if (pc == DW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_xormul64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_dword_xormul64_loop_target(0xCAFEBABEull));
    return 0;
}
```
