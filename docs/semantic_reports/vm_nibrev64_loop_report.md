# vm_nibrev64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_nibrev64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_nibrev64_loop.ll`
- **Symbol:** `vm_nibrev64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_nibrev64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_nibrev64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1, n=2 even -> identity |
| 3 | RCX=15 | 15 | 15 | 15 | yes | x=0xF, n=8 even -> identity |
| 4 | RCX=51966 | 17270178671059009536 | 17270178671059009536 | 17270178671059009536 | yes | x=0xCAFE, n=7 odd -> 0xEFAC0...0 |
| 5 | RCX=3405691582 | 16981930341944000512 | 16981930341944000512 | 16981930341944000512 | yes | x=0xCAFEBABE, n=7 odd |
| 6 | RCX=1311768467463790320 | 1147797409030816545 | 1147797409030816545 | 1147797409030816545 | yes | 0x123456789ABCDEF0, n=1 -> 0x0FEDCBA987654321 |
| 7 | RCX=1147797409030816545 | 1147797409030816545 | 1147797409030816545 | 1147797409030816545 | yes | already-reversed input, n=2 even -> identity |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | max u64: nibble-rev fixed point |
| 9 | RCX=11400714819323198485 | 11400714819323198485 | 11400714819323198485 | 11400714819323198485 | yes | K (golden), n=6 even -> identity |
| 10 | RCX=3735928559 | 3735928559 | 3735928559 | 3735928559 | yes | x=0xDEADBEEF, n=8 even -> identity |

## Source

```c
/* PC-state VM applying an i64 NIBBLE-REVERSE (16-way fan-in) for n
 * iterations.  Even-trip = identity, odd-trip = single nibble-reverse.
 *   for k in 0..n:
 *     result = 0
 *     for i in 0..16:
 *       nib = (state >> (i*4)) & 0xF
 *       result |= nib << ((15-i)*4)
 *     state = result
 * Outer trip n = (x & 7) + 1.  Inner is a fixed 16-iteration
 * fan-in/fan-out fully unrolled.
 * Lift target: vm_nibrev64_loop_target.
 *
 * Distinct from vm_bswap64_loop (byte-reverse: 8 bytes shuffled) and
 * vm_bitreverse64_loop (full bit-reverse, folds to llvm.bitreverse.i64).
 * Nibble-reverse is structurally between the two: 16 4-bit chunks
 * permuted, no LLVM intrinsic recognition expected.
 */
#include <stdio.h>
#include <stdint.h>

enum NbVmPc {
    NB_LOAD       = 0,
    NB_INIT       = 1,
    NB_LOOP_CHECK = 2,
    NB_LOOP_BODY  = 3,
    NB_LOOP_INC   = 4,
    NB_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_nibrev64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = NB_LOAD;

    while (1) {
        if (pc == NB_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = NB_INIT;
        } else if (pc == NB_INIT) {
            idx = 0;
            pc = NB_LOOP_CHECK;
        } else if (pc == NB_LOOP_CHECK) {
            pc = (idx < n) ? NB_LOOP_BODY : NB_HALT;
        } else if (pc == NB_LOOP_BODY) {
            uint64_t r = 0ull;
            r |= ((state >>  0) & 0xFull) << 60;
            r |= ((state >>  4) & 0xFull) << 56;
            r |= ((state >>  8) & 0xFull) << 52;
            r |= ((state >> 12) & 0xFull) << 48;
            r |= ((state >> 16) & 0xFull) << 44;
            r |= ((state >> 20) & 0xFull) << 40;
            r |= ((state >> 24) & 0xFull) << 36;
            r |= ((state >> 28) & 0xFull) << 32;
            r |= ((state >> 32) & 0xFull) << 28;
            r |= ((state >> 36) & 0xFull) << 24;
            r |= ((state >> 40) & 0xFull) << 20;
            r |= ((state >> 44) & 0xFull) << 16;
            r |= ((state >> 48) & 0xFull) << 12;
            r |= ((state >> 52) & 0xFull) <<  8;
            r |= ((state >> 56) & 0xFull) <<  4;
            r |= ((state >> 60) & 0xFull) <<  0;
            state = r;
            pc = NB_LOOP_INC;
        } else if (pc == NB_LOOP_INC) {
            idx = idx + 1;
            pc = NB_LOOP_CHECK;
        } else if (pc == NB_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_nibrev64(0xCAFE)=0x%llx vm_nibrev64(0x123456789ABCDEF0)=0x%llx\n",
           (unsigned long long)vm_nibrev64_loop_target(0xCAFEull),
           (unsigned long long)vm_nibrev64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
```
