# vm_hexdigits64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_hexdigits64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_hexdigits64_loop.ll`
- **Symbol:** `vm_hexdigits64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_hexdigits64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_hexdigits64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 1 | 1 | 1 | yes | x=0: special-case 1 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1 |
| 3 | RCX=15 | 1 | 1 | 1 | yes | x=0xF: 1 nibble |
| 4 | RCX=16 | 2 | 2 | 2 | yes | x=0x10: 2 nibbles |
| 5 | RCX=255 | 2 | 2 | 2 | yes | x=0xFF |
| 6 | RCX=4095 | 3 | 3 | 3 | yes | x=0xFFF |
| 7 | RCX=51966 | 4 | 4 | 4 | yes | x=0xCAFE |
| 8 | RCX=3405691582 | 8 | 8 | 8 | yes | x=0xCAFEBABE |
| 9 | RCX=18446744073709551615 | 16 | 16 | 16 | yes | max u64: 16 nibbles |
| 10 | RCX=11400714819323198485 | 16 | 16 | 16 | yes | K (golden, MSB set) |

## Source

```c
/* PC-state VM that counts hex digits (nibbles) of x via repeated >>4.
 *   if (x == 0) return 1;
 *   count = 0;
 *   while (state > 0) { state >>= 4; count++; }
 *   return count;
 * Variable trip 1..16.
 * Lift target: vm_hexdigits64_loop_target.
 *
 * Distinct from vm_decdigits64_loop (constant divisor 10 with udiv-by-10
 * magic-number fold) and vm_clz64_loop (single-bit shift): uses 4-bit
 * stride lshr with > 0 termination.  The optimizer may fold the loop to
 * llvm.ctlz-based digit-count; conservative patterns are lshr + icmp.
 */
#include <stdio.h>
#include <stdint.h>

enum HxVmPc {
    HX_LOAD       = 0,
    HX_ZERO_CHECK = 1,
    HX_LOOP_CHECK = 2,
    HX_LOOP_BODY  = 3,
    HX_HALT       = 4,
};

__declspec(noinline)
int vm_hexdigits64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = HX_LOAD;

    while (1) {
        if (pc == HX_LOAD) {
            state = x;
            count = 0;
            pc = HX_ZERO_CHECK;
        } else if (pc == HX_ZERO_CHECK) {
            if (state == 0ull) {
                count = 1;
                pc = HX_HALT;
            } else {
                pc = HX_LOOP_CHECK;
            }
        } else if (pc == HX_LOOP_CHECK) {
            pc = (state > 0ull) ? HX_LOOP_BODY : HX_HALT;
        } else if (pc == HX_LOOP_BODY) {
            state = state >> 4;
            count = count + 1;
            pc = HX_LOOP_CHECK;
        } else if (pc == HX_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_hexdigits64(0xCAFEBABE)=%d vm_hexdigits64(max)=%d\n",
           vm_hexdigits64_loop_target(0xCAFEBABEull),
           vm_hexdigits64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
