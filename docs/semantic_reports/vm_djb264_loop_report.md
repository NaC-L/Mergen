# vm_djb264_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_djb264_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_djb264_loop.ll`
- **Symbol:** `vm_djb264_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_djb264_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_djb264_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 177573 | 177573 | 177573 | yes | x=0, n=1: 5381*33+0 |
| 2 | RCX=1 | 5859942 | 5859942 | 5859942 | yes | x=1, n=2 |
| 3 | RCX=7 | 7568183103855660 | 7568183103855660 | 7568183103855660 | yes | x=7, n=8 (max) |
| 4 | RCX=255 | 7578752477713956 | 7578752477713956 | 7578752477713956 | yes | x=0xFF, n=8 |
| 5 | RCX=51966 | 229665779872749 | 229665779872749 | 229665779872749 | yes | x=0xCAFE, n=7 |
| 6 | RCX=3405691582 | 229582808239653 | 229582808239653 | 229582808239653 | yes | x=0xCAFEBABE, n=7 |
| 7 | RCX=1311768467463790320 | 177813 | 177813 | 177813 | yes | x=0x123...DEF0, n=1: low byte 0xF0 |
| 8 | RCX=18446744073709551615 | 7579092093431421 | 7579092093431421 | 7579092093431421 | yes | max u64, n=8 |
| 9 | RCX=11400714819323198485 | 6950360842513 | 6950360842513 | 6950360842513 | yes | x=K (golden ratio), n=6 |
| 10 | RCX=3735928559 | 7578322995237885 | 7578322995237885 | 7578322995237885 | yes | x=0xDEADBEEF, n=8 |

## Source

```c
/* PC-state VM running an i64 djb2-style hash over the bytes of x.
 *   h = 5381;
 *   for i in 0..n: { b = (x >> (i*8)) & 0xFF; h = h * 33 + b; }
 *   return h;
 * Where n = (x & 7) + 1 (1..8 bytes consumed).  Returns full uint64_t.
 * Lift target: vm_djb264_loop_target.
 *
 * Distinct from vm_djb2_loop (i32 hash): exercises i64 mul-by-33 + i64
 * add inside a variable-trip loop body that also performs a symbolic
 * shift-by-loop-counter byte extraction.
 */
#include <stdio.h>
#include <stdint.h>

enum DjVmPc {
    DJ_LOAD       = 0,
    DJ_INIT       = 1,
    DJ_LOOP_CHECK = 2,
    DJ_LOOP_BODY  = 3,
    DJ_LOOP_INC   = 4,
    DJ_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_djb264_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t h   = 0;
    uint64_t xx  = 0;
    int      pc  = DJ_LOAD;

    while (1) {
        if (pc == DJ_LOAD) {
            n  = (int)(x & 7ull) + 1;
            xx = x;
            h  = 5381ull;
            pc = DJ_INIT;
        } else if (pc == DJ_INIT) {
            idx = 0;
            pc = DJ_LOOP_CHECK;
        } else if (pc == DJ_LOOP_CHECK) {
            pc = (idx < n) ? DJ_LOOP_BODY : DJ_HALT;
        } else if (pc == DJ_LOOP_BODY) {
            uint64_t b = (xx >> (idx * 8)) & 0xFFull;
            h = h * 33ull + b;
            pc = DJ_LOOP_INC;
        } else if (pc == DJ_LOOP_INC) {
            idx = idx + 1;
            pc = DJ_LOOP_CHECK;
        } else if (pc == DJ_HALT) {
            return h;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_djb264(0xCAFEBABE)=%llu vm_djb264(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_djb264_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_djb264_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
