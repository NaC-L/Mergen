# vm_bswap64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bswap64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bswap64_loop.ll`
- **Symbol:** `vm_bswap64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bswap64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bswap64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: zero stays zero |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1, n=2: double bswap = identity |
| 3 | RCX=2 | 144115188075855872 | 144115188075855872 | 144115188075855872 | yes | x=2, n=3: bswap once -> 0x0200...0 |
| 4 | RCX=7 | 7 | 7 | 7 | yes | x=7, n=8: even -> identity |
| 5 | RCX=255 | 255 | 255 | 255 | yes | x=0xFF, n=8: even -> identity |
| 6 | RCX=51966 | 18359486830929248256 | 18359486830929248256 | 18359486830929248256 | yes | x=0xCAFE, n=7 (odd) -> 0xFECA00..0 |
| 7 | RCX=3405691582 | 13743577356411338752 | 13743577356411338752 | 13743577356411338752 | yes | x=0xCAFEBABE, n=7 (odd) |
| 8 | RCX=1311768467463790320 | 17356517385562371090 | 17356517385562371090 | 17356517385562371090 | yes | 0x123...DEF0, n=1: bswap once |
| 9 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | max u64: bswap fixed point |
| 10 | RCX=11400714819323198485 | 11400714819323198485 | 11400714819323198485 | 11400714819323198485 | yes | K (golden): n=6 even -> identity |

## Source

```c
/* PC-state VM running an i64 byte-swap built from explicit shifts and
 * masks (no intrinsic) in a variable-trip loop.  Even-trip values produce
 * identity; odd-trip values produce a single byte-swap of the input.
 *   for i in 0..n: state = byteswap_via_shifts_and_masks(state)
 * Variable trip n = (x & 7) + 1.
 * Lift target: vm_bswap64_loop_target.
 *
 * Distinct from vm_imported_bswap_loop (i32 _byteswap_ulong intrinsic):
 * exercises the explicit 8-way mask+shift+or fan-in lowering on full i64
 * state.  The lifter likely recognizes this as llvm.bswap.i64 after
 * optimization.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_LOAD       = 0,
    BS_INIT       = 1,
    BS_LOOP_CHECK = 2,
    BS_LOOP_BODY  = 3,
    BS_LOOP_INC   = 4,
    BS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_bswap64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = BS_LOAD;

    while (1) {
        if (pc == BS_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = BS_INIT;
        } else if (pc == BS_INIT) {
            idx = 0;
            pc = BS_LOOP_CHECK;
        } else if (pc == BS_LOOP_CHECK) {
            pc = (idx < n) ? BS_LOOP_BODY : BS_HALT;
        } else if (pc == BS_LOOP_BODY) {
            state = ((state & 0x00000000000000FFull) << 56) |
                    ((state & 0x000000000000FF00ull) << 40) |
                    ((state & 0x0000000000FF0000ull) << 24) |
                    ((state & 0x00000000FF000000ull) << 8)  |
                    ((state & 0x000000FF00000000ull) >> 8)  |
                    ((state & 0x0000FF0000000000ull) >> 24) |
                    ((state & 0x00FF000000000000ull) >> 40) |
                    ((state & 0xFF00000000000000ull) >> 56);
            pc = BS_LOOP_INC;
        } else if (pc == BS_LOOP_INC) {
            idx = idx + 1;
            pc = BS_LOOP_CHECK;
        } else if (pc == BS_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bswap64(0x123456789ABCDEF0)=0x%llx vm_bswap64(0xCAFE)=0x%llx\n",
           (unsigned long long)vm_bswap64_loop_target(0x123456789ABCDEF0ull),
           (unsigned long long)vm_bswap64_loop_target(0xCAFEull));
    return 0;
}
```
