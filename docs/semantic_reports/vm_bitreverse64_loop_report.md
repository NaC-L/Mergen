# vm_bitreverse64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bitreverse64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bitreverse64_loop.ll`
- **Symbol:** `vm_bitreverse64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bitreverse64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bitreverse64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: zero stays zero |
| 2 | RCX=1 | 9223372036854775808 | 9223372036854775808 | 9223372036854775808 | yes | x=1 -> MSB |
| 3 | RCX=255 | 18374686479671623680 | 18374686479671623680 | 18374686479671623680 | yes | x=0xFF -> top byte |
| 4 | RCX=9223372036854775808 | 1 | 1 | 1 | yes | x=2^63 -> 1 (MSB to LSB) |
| 5 | RCX=51966 | 9174676865883832320 | 9174676865883832320 | 9174676865883832320 | yes | x=0xCAFE |
| 6 | RCX=3405691582 | 9033516422034096128 | 9033516422034096128 | 9033516422034096128 | yes | x=0xCAFEBABE |
| 7 | RCX=1311768467463790320 | 1115552785675988040 | 1115552785675988040 | 1115552785675988040 | yes | 0x123...DEF0 |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | max u64: bitreverse fixed point |
| 9 | RCX=11400714819323198485 | 12123218500447562873 | 12123218500447562873 | 12123218500447562873 | yes | x=K (golden ratio) |
| 10 | RCX=12297829382473034410 | 6148914691236517205 | 6148914691236517205 | 6148914691236517205 | yes | 0xAAAA... -> 0x5555... |

## Source

```c
/* PC-state VM running an i64 bit-reverse via a 64-trip shift+or loop.
 *   result = 0;
 *   for i in 0..64:
 *     result = (result << 1) | (state & 1);
 *     state  = state >> 1;
 *   return result;
 * Lift target: vm_bitreverse64_loop_target.
 *
 * Distinct from vm_bitreverse_loop (i32 version, lifter recognizes
 * llvm.bitreverse.i8): exercises a 64-trip explicit fan-in shift+or +
 * shift-right body on full i64 state.  May or may not be recognized as
 * llvm.bitreverse.i64 by the optimizer.
 */
#include <stdio.h>
#include <stdint.h>

enum BrVmPc {
    BR_LOAD       = 0,
    BR_INIT       = 1,
    BR_LOOP_CHECK = 2,
    BR_LOOP_BODY  = 3,
    BR_LOOP_INC   = 4,
    BR_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_bitreverse64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t state  = 0;
    uint64_t result = 0;
    int      pc     = BR_LOAD;

    while (1) {
        if (pc == BR_LOAD) {
            state  = x;
            result = 0ull;
            pc = BR_INIT;
        } else if (pc == BR_INIT) {
            idx = 0;
            pc = BR_LOOP_CHECK;
        } else if (pc == BR_LOOP_CHECK) {
            pc = (idx < 64) ? BR_LOOP_BODY : BR_HALT;
        } else if (pc == BR_LOOP_BODY) {
            result = (result << 1) | (state & 1ull);
            state  = state >> 1;
            pc = BR_LOOP_INC;
        } else if (pc == BR_LOOP_INC) {
            idx = idx + 1;
            pc = BR_LOOP_CHECK;
        } else if (pc == BR_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bitreverse64(1)=0x%llx vm_bitreverse64(0xCAFE)=0x%llx\n",
           (unsigned long long)vm_bitreverse64_loop_target(1ull),
           (unsigned long long)vm_bitreverse64_loop_target(0xCAFEull));
    return 0;
}
```
