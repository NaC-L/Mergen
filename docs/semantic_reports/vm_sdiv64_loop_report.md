# vm_sdiv64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_sdiv64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_sdiv64_loop.ll`
- **Symbol:** `vm_sdiv64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_sdiv64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_sdiv64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0: 0 trips (val !> 0) |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1, div=3: 1/3=0 -> 1 trip |
| 3 | RCX=10 | 2 | 2 | 2 | yes | x=10, div=4: 10->2->0 |
| 4 | RCX=100 | 3 | 3 | 3 | yes | x=100, div=6: 100->16->2->0 |
| 5 | RCX=1000 | 10 | 10 | 10 | yes | x=1000, div=2: log2(1000)+1 |
| 6 | RCX=51966 | 6 | 6 | 6 | yes | x=0xCAFE, div=8 |
| 7 | RCX=3405691582 | 11 | 11 | 11 | yes | x=0xCAFEBABE, div=8 |
| 8 | RCX=18446744073709551615 | 0 | 0 | 0 | yes | max u64 -> -1 signed: 0 trips |
| 9 | RCX=9223372036854775807 | 20 | 20 | 20 | yes | INT64_MAX, div=9 |
| 10 | RCX=1311768467463790320 | 61 | 61 | 61 | yes | 0x123...DEF0, div=2 |

## Source

```c
/* PC-state VM that counts SIGNED divisions of state by a small divisor
 * until state becomes non-positive.
 *   divisor = (x & 7) + 2;     // 2..9
 *   val     = (int64_t)x;
 *   count   = 0;
 *   while (val > 0) { val = val / divisor; count++; }
 *   return count;
 * Lift target: vm_sdiv64_loop_target.
 *
 * Distinct from vm_divcount64_loop (unsigned udiv with `state >= divisor`):
 * exercises i64 sdiv + signed comparison `val > 0` (icmp sgt) inside a
 * data-dependent loop.  Negative inputs (e.g. max u64 reads as -1) take
 * 0 trips because the signed comparison fails immediately.
 */
#include <stdio.h>
#include <stdint.h>

enum SdVmPc {
    SD_LOAD       = 0,
    SD_LOOP_CHECK = 1,
    SD_LOOP_BODY  = 2,
    SD_HALT       = 3,
};

__declspec(noinline)
int vm_sdiv64_loop_target(int64_t x) {
    int64_t divisor = 0;
    int64_t val     = 0;
    int     count   = 0;
    int     pc      = SD_LOAD;

    while (1) {
        if (pc == SD_LOAD) {
            divisor = (int64_t)((uint64_t)x & 7ull) + 2;
            val     = x;
            count   = 0;
            pc = SD_LOOP_CHECK;
        } else if (pc == SD_LOOP_CHECK) {
            pc = (val > 0) ? SD_LOOP_BODY : SD_HALT;
        } else if (pc == SD_LOOP_BODY) {
            val = val / divisor;
            count = count + 1;
            pc = SD_LOOP_CHECK;
        } else if (pc == SD_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_sdiv64(1000)=%d vm_sdiv64(0x7FFFFFFFFFFFFFFF)=%d\n",
           vm_sdiv64_loop_target((int64_t)1000),
           vm_sdiv64_loop_target((int64_t)0x7FFFFFFFFFFFFFFFll));
    return 0;
}
```
