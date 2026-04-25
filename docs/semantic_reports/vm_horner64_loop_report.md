# vm_horner64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_horner64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_horner64_loop.ll`
- **Symbol:** `vm_horner64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_horner64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_horner64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: zero state |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1, n=2, p=1: linear |
| 3 | RCX=255 | 255 | 255 | 255 | yes | x=0xFF, n=8, p=1: 0xFF*1^7 |
| 4 | RCX=511 | 32704 | 32704 | 32704 | yes | x=0x1FF, n=8, p=2 |
| 5 | RCX=51966 | 17844649336662652 | 17844649336662652 | 17844649336662652 | yes | x=0xCAFE, n=7, p=0xCB |
| 6 | RCX=3405691582 | 8167467842758312 | 8167467842758312 | 8167467842758312 | yes | x=0xCAFEBABE, n=7, p=0xBC |
| 7 | RCX=1311768467463790320 | 240 | 240 | 240 | yes | x=0x123...DEF0, n=1, p=0xDF |
| 8 | RCX=18446744073709551615 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | max u64, n=8, p=0x100: telescope wraps |
| 9 | RCX=11400714819323198485 | 671289116996 | 671289116996 | 671289116996 | yes | x=K (golden), n=6, p=0x7D |
| 10 | RCX=21930 | 1264630 | 1264630 | 1264630 | yes | x=0x55AA, n=3, p=0x56 |

## Source

```c
/* PC-state VM running Horner-style polynomial evaluation on full uint64_t.
 *   p = ((x >> 8) & 0xFF) + 1;
 *   n = (x & 7) + 2;
 *   for i in 0..n: { c = (x >> (i*8)) & 0xFF; s = s * p + c; }
 *   return s;
 * Returns full uint64_t.  Lift target: vm_horner64_loop_target.
 *
 * Distinct from vm_horner_signed_loop (i32 signed Horner).  Exercises
 * i64 mul + add inside a variable-trip loop with byte-walking shift
 * (loop-counter-derived shift amount).
 */
#include <stdio.h>
#include <stdint.h>

enum HnVmPc {
    HN_LOAD       = 0,
    HN_INIT       = 1,
    HN_LOOP_CHECK = 2,
    HN_LOOP_BODY  = 3,
    HN_LOOP_INC   = 4,
    HN_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_horner64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t p   = 0;
    uint64_t s   = 0;
    uint64_t xx  = 0;
    int      pc  = HN_LOAD;

    while (1) {
        if (pc == HN_LOAD) {
            n  = (int)(x & 7ull) + 1;
            p  = ((x >> 8) & 0xFFull) + 1ull;
            xx = x;
            s  = 0ull;
            pc = HN_INIT;
        } else if (pc == HN_INIT) {
            idx = 0;
            pc = HN_LOOP_CHECK;
        } else if (pc == HN_LOOP_CHECK) {
            pc = (idx < n) ? HN_LOOP_BODY : HN_HALT;
        } else if (pc == HN_LOOP_BODY) {
            uint64_t c = (xx >> (idx * 8)) & 0xFFull;
            s = s * p + c;
            pc = HN_LOOP_INC;
        } else if (pc == HN_LOOP_INC) {
            idx = idx + 1;
            pc = HN_LOOP_CHECK;
        } else if (pc == HN_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_horner64(0xCAFE)=%llu vm_horner64(0x1FF)=%llu\n",
           (unsigned long long)vm_horner64_loop_target(0xCAFEull),
           (unsigned long long)vm_horner64_loop_target(0x1FFull));
    return 0;
}
```
