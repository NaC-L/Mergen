# vm_dynshl_pack64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_dynshl_pack64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_dynshl_pack64_loop.ll`
- **Symbol:** `vm_dynshl_pack64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_dynshl_pack64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_dynshl_pack64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: chunk0=1 << 0; chunk1=0 |
| 3 | RCX=2 | 2 | 2 | 2 | yes | x=2 n=3: chunk0=2; chunk1=0; chunk2=0 |
| 4 | RCX=7 | 1 | 1 | 1 | yes | x=7 n=8: chunks [3,1,0,...] xor placed -> 0b11 ^ (0b01<<1)=0b01 |
| 5 | RCX=8 | 0 | 0 | 0 | yes | x=8 n=1: chunk0=0 |
| 6 | RCX=3405691582 | 184 | 184 | 184 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 405 | 405 | 405 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 257 | 257 | 257 | yes | all 0xFF: n=8 chunks all 0b11 xor stack |
| 9 | RCX=72623859790382856 | 0 | 0 | 0 | yes | 0x0102...0708: n=1 chunk0=00 |
| 10 | RCX=1311768467463790320 | 0 | 0 | 0 | yes | 0x12345...EF0: n=1 chunk0=0 |

## Source

```c
/* PC-state VM that XOR-packs 2-bit chunks of x into r at DYNAMIC bit
 * positions controlled by the loop index:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0x3) << i);   // dynamic shl amount = i
 *     s >>= 2;
 *   }
 *   return r;
 *
 * Lift target: vm_dynshl_pack64_loop_target.
 *
 * Distinct from vm_bitfetch_window64_loop (dynamic LSHR amount): this
 * sample exercises the complementary `shl i64 v, %i` where %i is the
 * loop-index phi.  Each iter's 2-bit chunk lands at a different bit
 * offset, so the lifter cannot fold the shift to a constant amount.
 * Combined with XOR accumulator and lshr-2 byte source.
 */
#include <stdio.h>
#include <stdint.h>

enum DsVmPc {
    DS_INIT_ALL = 0,
    DS_CHECK    = 1,
    DS_BODY     = 2,
    DS_INC      = 3,
    DS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynshl_pack64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DS_INIT_ALL;

    while (1) {
        if (pc == DS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DS_CHECK;
        } else if (pc == DS_CHECK) {
            pc = (i < n) ? DS_BODY : DS_HALT;
        } else if (pc == DS_BODY) {
            r = r ^ ((s & 0x3ull) << i);
            s = s >> 2;
            pc = DS_INC;
        } else if (pc == DS_INC) {
            i = i + 1ull;
            pc = DS_CHECK;
        } else if (pc == DS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynshl_pack64(0xFF)=%llu\n",
           (unsigned long long)vm_dynshl_pack64_loop_target(0xFFull));
    return 0;
}
```
