# vm_bytecyc64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bytecyc64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bytecyc64_loop.ll`
- **Symbol:** `vm_bytecyc64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bytecyc64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bytecyc64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1, shift=0: identity |
| 3 | RCX=255 | 255 | 255 | 255 | yes | x=0xFF, shift=0 |
| 4 | RCX=72623859790382856 | 144964032628459521 | 144964032628459521 | 144964032628459521 | yes | 0x0102030405060708, shift=1: rotates bytes |
| 5 | RCX=3405691582 | 3405691582 | 3405691582 | 3405691582 | yes | 0xCAFEBABE: shift=0 identity |
| 6 | RCX=14627333968688430831 | 13456437574443715326 | 13456437574443715326 | 13456437574443715326 | yes | 0xCAFEBABEDEADBEEF, shift=2 |
| 7 | RCX=1311768467463790320 | 6230900220451885620 | 6230900220451885620 | 6230900220451885620 | yes | 0x123456789ABCDEF0, shift=2 |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | max u64: rotation invariant |
| 9 | RCX=11400714819323198485 | 8941226596316577610 | 8941226596316577610 | 8941226596316577610 | yes | K (golden), shift=6 |
| 10 | RCX=4822678189205111 | 4822678189205111 | 4822678189205111 | 4822678189205111 | yes | 0x0011223344556677, shift=0 |

## Source

```c
/* PC-state VM that cyclically shifts BYTES of x by an input-derived
 * amount (top byte bits 0..2 select the rotation).
 *   shift = (x >> 56) & 7;
 *   result = 0;
 *   for i in 0..8:
 *     byte = (x >> (i*8)) & 0xFF
 *     result |= byte << (((i + shift) & 7) * 8)
 *   return result;
 * Lift target: vm_bytecyc64_loop_target.
 *
 * Distinct from vm_bswap64_loop (full 8-byte reverse) and vm_rotl64_loop
 * (bit-level rotation): byte-granularity cyclic permutation with
 * input-derived shift amount.  Each byte goes to position (i+shift)&7.
 */
#include <stdio.h>
#include <stdint.h>

enum BcVmPc {
    BC_LOAD       = 0,
    BC_INIT       = 1,
    BC_LOOP_CHECK = 2,
    BC_LOOP_BODY  = 3,
    BC_LOOP_INC   = 4,
    BC_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_bytecyc64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t shift  = 0;
    uint64_t result = 0;
    int      pc     = BC_LOAD;

    while (1) {
        if (pc == BC_LOAD) {
            xx     = x;
            shift  = (x >> 56) & 7ull;
            result = 0ull;
            pc = BC_INIT;
        } else if (pc == BC_INIT) {
            idx = 0;
            pc = BC_LOOP_CHECK;
        } else if (pc == BC_LOOP_CHECK) {
            pc = (idx < 8) ? BC_LOOP_BODY : BC_HALT;
        } else if (pc == BC_LOOP_BODY) {
            uint64_t byte = (xx >> (idx * 8)) & 0xFFull;
            uint64_t pos  = ((uint64_t)idx + shift) & 7ull;
            result = result | (byte << (pos * 8));
            pc = BC_LOOP_INC;
        } else if (pc == BC_LOOP_INC) {
            idx = idx + 1;
            pc = BC_LOOP_CHECK;
        } else if (pc == BC_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytecyc64(0x0102030405060708)=0x%llx vm_bytecyc64(0xCAFEBABEDEADBEEF)=0x%llx\n",
           (unsigned long long)vm_bytecyc64_loop_target(0x0102030405060708ull),
           (unsigned long long)vm_bytecyc64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
```
