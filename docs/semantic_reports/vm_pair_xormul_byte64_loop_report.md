# vm_pair_xormul_byte64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_pair_xormul_byte64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_pair_xormul_byte64_loop.ll`
- **Symbol:** `vm_pair_xormul_byte64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_pair_xormul_byte64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_pair_xormul_byte64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | all zero -> 0 (b0=b1=0) |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 n=2: pair (1,0) -> 1*1=1; pair (0,0)=0 |
| 3 | RCX=2 | 4 | 4 | 4 | yes | x=2 n=3: pair (2,0) |
| 4 | RCX=3 | 9 | 9 | 9 | yes | x=3 n=4: pair (3,0) |
| 5 | RCX=3405691582 | 25216 | 25216 | 25216 | yes | 0xCAFEBABE: n=3, pairs (BE,BA)+(FE,CA)+(0,0) |
| 6 | RCX=3735928559 | 80174 | 80174 | 80174 | yes | 0xDEADBEEF: n=4 |
| 7 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | all 0xFF: each pair (FF,FF) -> 0^0=0 |
| 8 | RCX=72623859790382856 | 225 | 225 | 225 | yes | 0x0102...0708: n=1 pair (8,7) -> 15*15=225 |
| 9 | RCX=1311768467463790320 | 21252 | 21252 | 21252 | yes | 0x12345...EF0: n=1 pair (F0,DE) -> 0x2E*0x1CE=21252 |
| 10 | RCX=18364758544493064720 | 2244 | 2244 | 2244 | yes | 0xFEDCBA9876543210: n=1 pair (10,32) -> 0x22*0x42=2244 |

## Source

```c
/* PC-state VM that processes consecutive byte pairs per iteration:
 *
 *   n = (x & 3) + 1;     // 1..4 pair iterations (up to 4 pairs of bytes)
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b0 = s & 0xFF;
 *     uint64_t b1 = (s >> 8) & 0xFF;
 *     r = r + (b0 ^ b1) * (b0 + b1);
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_pair_xormul_byte64_loop_target.
 *
 * Distinct from:
 *   - All single-byte-per-iter samples (consume 1 byte each iter)
 *   - vm_xormul_byte_idx64_loop (one byte * counter)
 *   - vm_bytesq_sum64_loop      (single-byte squared)
 *
 * Tests TWO byte reads per iteration (b0, b1 from s and s>>8) combined
 * via XOR (b0^b1) and ADD (b0+b1) then MULTIPLY together and ADD-fold.
 * For equal-byte pairs the XOR is 0 so contribution is 0.  Trip count
 * uses `& 3` so loop runs 1..4 times consuming 2 bytes each iter.
 */
#include <stdio.h>
#include <stdint.h>

enum PpVmPc {
    PP_INIT_ALL = 0,
    PP_CHECK    = 1,
    PP_BODY     = 2,
    PP_INC      = 3,
    PP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_pair_xormul_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = PP_INIT_ALL;

    while (1) {
        if (pc == PP_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = PP_CHECK;
        } else if (pc == PP_CHECK) {
            pc = (i < n) ? PP_BODY : PP_HALT;
        } else if (pc == PP_BODY) {
            uint64_t b0 = s & 0xFFull;
            uint64_t b1 = (s >> 8) & 0xFFull;
            r = r + (b0 ^ b1) * (b0 + b1);
            s = s >> 16;
            pc = PP_INC;
        } else if (pc == PP_INC) {
            i = i + 1ull;
            pc = PP_CHECK;
        } else if (pc == PP_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pair_xormul_byte64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_pair_xormul_byte64_loop_target(0xCAFEBABEull));
    return 0;
}
```
