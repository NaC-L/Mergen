# vm_orsum_byte_idx64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_orsum_byte_idx64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_orsum_byte_idx64_loop.ll`
- **Symbol:** `vm_orsum_byte_idx64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_orsum_byte_idx64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_orsum_byte_idx64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | x=0 n=1: 0\|0\|1=1 |
| 2 | RCX=1 | 3 | 3 | 3 | yes | x=1 n=2: 0\|1\|1=1; \|0\|2=3 |
| 3 | RCX=2 | 3 | 3 | 3 | yes | x=2 n=3: bytes [2,0,0] \| counters [1,2,3] |
| 4 | RCX=7 | 15 | 15 | 15 | yes | x=7 n=8: 7 \| (1\|2\|...\|8) = 7\|15 = 15 |
| 5 | RCX=8 | 9 | 9 | 9 | yes | x=8 n=1: 8\|1=9 |
| 6 | RCX=3405691582 | 255 | 255 | 255 | yes | 0xCAFEBABE: n=7 OR of high-byte BE=0xBE \| counters fills low 8 bits |
| 7 | RCX=3735928559 | 255 | 255 | 255 | yes | 0xDEADBEEF: n=8 fills low 8 bits |
| 8 | RCX=18446744073709551615 | 255 | 255 | 255 | yes | all 0xFF: low byte already 0xFF -> 0xFF |
| 9 | RCX=72623859790382856 | 9 | 9 | 9 | yes | 0x0102...0708: n=1 byte0=8 \| 1=9 |
| 10 | RCX=1311768467463790320 | 241 | 241 | 241 | yes | 0x12345...EF0: n=1 byte0=0xF0 \| 1=0xF1=241 |

## Source

```c
/* PC-state VM that ORs bytes and counter values into a single
 * accumulator over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r | ((s & 0xFF) | (i + 1));   // OR-accumulator
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_orsum_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_byte_idx64_loop  (XOR fold of byte * counter)
 *   - vm_andsum_byte_idx64_loop  (AND of byte with counter, ADD-folded)
 *   - vm_uintadd_byte_idx64_loop (ADD of byte * counter)
 *
 * Tests `or i64` of zext-byte with phi-tracked counter (i+1) folded
 * via OR-accumulator.  Unlike XOR which can cancel, OR is monotone
 * (only sets bits).  Counter values 1..8 contribute fixed low bits
 * regardless of byte content.
 */
#include <stdio.h>
#include <stdint.h>

enum OsVmPc {
    OS_INIT_ALL = 0,
    OS_CHECK    = 1,
    OS_BODY     = 2,
    OS_INC      = 3,
    OS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_orsum_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = OS_INIT_ALL;

    while (1) {
        if (pc == OS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = OS_CHECK;
        } else if (pc == OS_CHECK) {
            pc = (i < n) ? OS_BODY : OS_HALT;
        } else if (pc == OS_BODY) {
            r = r | ((s & 0xFFull) | (i + 1ull));
            s = s >> 8;
            pc = OS_INC;
        } else if (pc == OS_INC) {
            i = i + 1ull;
            pc = OS_CHECK;
        } else if (pc == OS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_orsum_byte_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_orsum_byte_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
