# vm_lfsr64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_lfsr64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_lfsr64_loop.ll`
- **Symbol:** `vm_lfsr64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_lfsr64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_lfsr64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 9223372036854775808 | 9223372036854775808 | 9223372036854775808 | yes | x=0: state=1, n=1: bit=1 shifted to MSB |
| 2 | RCX=1 | 4611686018427387904 | 4611686018427387904 | 4611686018427387904 | yes | x=1, n=2 |
| 3 | RCX=7 | 288230376151711744 | 288230376151711744 | 288230376151711744 | yes | x=7, n=8 |
| 4 | RCX=15 | 2533274790395904 | 2533274790395904 | 2533274790395904 | yes | x=0xF, n=16 max |
| 5 | RCX=51966 | 8421731303182827521 | 8421731303182827521 | 8421731303182827521 | yes | x=0xCAFE, n=15 |
| 6 | RCX=3405691582 | 13130244713598785021 | 13130244713598785021 | 13130244713598785021 | yes | x=0xCAFEBABE, n=15 |
| 7 | RCX=1311768467463790320 | 655884233731895160 | 655884233731895160 | 655884233731895160 | yes | 0x123...DEF0, n=1 |
| 8 | RCX=18446744073709551615 | 281474976710655 | 281474976710655 | 281474976710655 | yes | max u64, n=16: clears top 16 bits |
| 9 | RCX=11400714819323198485 | 8248586701299853808 | 8248586701299853808 | 8248586701299853808 | yes | x=K (golden), n=6 |
| 10 | RCX=3735928559 | 984880943510642349 | 984880943510642349 | 984880943510642349 | yes | x=0xDEADBEEF, n=16 |

## Source

```c
/* PC-state VM running a 64-bit LFSR with maximal-length feedback taps
 * at positions 0, 1, 3, 4.
 *   state = x | 1;   // ensure non-zero
 *   n = (x & 0xF) + 1;
 *   for i in 0..n:
 *     bit = ((state) ^ (state>>1) ^ (state>>3) ^ (state>>4)) & 1
 *     state = (state >> 1) | (bit << 63);
 *   return state;
 * Lift target: vm_lfsr64_loop_target.
 *
 * Distinct from vm_lfsr_loop (i32 LFSR): exercises full 64-bit state
 * with multi-bit XOR feedback computation and a high-bit OR-merge.
 */
#include <stdio.h>
#include <stdint.h>

enum LfVmPc {
    LF_LOAD       = 0,
    LF_INIT       = 1,
    LF_LOOP_CHECK = 2,
    LF_LOOP_BODY  = 3,
    LF_LOOP_INC   = 4,
    LF_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_lfsr64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = LF_LOAD;

    while (1) {
        if (pc == LF_LOAD) {
            state = x | 1ull;
            n     = (int)(x & 0xFull) + 1;
            pc = LF_INIT;
        } else if (pc == LF_INIT) {
            idx = 0;
            pc = LF_LOOP_CHECK;
        } else if (pc == LF_LOOP_CHECK) {
            pc = (idx < n) ? LF_LOOP_BODY : LF_HALT;
        } else if (pc == LF_LOOP_BODY) {
            uint64_t bit = (state ^ (state >> 1) ^ (state >> 3) ^ (state >> 4)) & 1ull;
            state = (state >> 1) | (bit << 63);
            pc = LF_LOOP_INC;
        } else if (pc == LF_LOOP_INC) {
            idx = idx + 1;
            pc = LF_LOOP_CHECK;
        } else if (pc == LF_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_lfsr64(0xCAFE)=0x%llx vm_lfsr64(0xFF)=0x%llx\n",
           (unsigned long long)vm_lfsr64_loop_target(0xCAFEull),
           (unsigned long long)vm_lfsr64_loop_target(0xFFull));
    return 0;
}
```
