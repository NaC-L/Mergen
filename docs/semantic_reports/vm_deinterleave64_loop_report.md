# vm_deinterleave64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_deinterleave64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_deinterleave64_loop.ll`
- **Symbol:** `vm_deinterleave64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_deinterleave64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_deinterleave64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 |
| 2 | RCX=1 | 1 | 1 | 1 | yes | x=1: bit 0 -> evens bit 0 |
| 3 | RCX=2 | 4294967296 | 4294967296 | 4294967296 | yes | x=2: bit 1 -> odds bit 0 -> 1<<32 |
| 4 | RCX=3 | 4294967297 | 4294967297 | 4294967297 | yes | x=3: both bit 0 of evens and odds |
| 5 | RCX=2863311530 | 281470681743360 | 281470681743360 | 281470681743360 | yes | x=0xAAAAAAAA: all to odds, evens=0 |
| 6 | RCX=1431655765 | 65535 | 65535 | 65535 | yes | x=0x55555555: all to evens, odds=0 |
| 7 | RCX=4294967295 | 281470681808895 | 281470681808895 | 281470681808895 | yes | x=0xFFFFFFFF: 0xFFFF in both halves |
| 8 | RCX=3405691582 | 211101937602118 | 211101937602118 | 211101937602118 | yes | x=0xCAFEBABE |
| 9 | RCX=2654435769 | 199484051056597 | 199484051056597 | 199484051056597 | yes | x=0x9E3779B9 |
| 10 | RCX=305419896 | 22084721854188 | 22084721854188 | 22084721854188 | yes | x=0x12345678 |

## Source

```c
/* PC-state VM that deinterleaves alternating bits of low 32 bits of x:
 * places even-indexed source bits into low 32 of result, odd-indexed
 * source bits into high 32 of result.
 *   evens = 0;  odds = 0;
 *   for i in 0..32:
 *     evens |= ((x >> (2*i))   & 1) << i;
 *     odds  |= ((x >> (2*i+1)) & 1) << i;
 *   return (odds << 32) | evens;
 * 32-trip fixed loop with FOUR shifts and two OR accumulators.
 * Lift target: vm_deinterleave64_loop_target.
 *
 * Distinct from vm_morton64_loop (interleave/spread one stream into
 * every-other position): this is the INVERSE - splits one input into
 * two streams.  Both accumulator slots update unconditionally with OR
 * (no mutually-exclusive branches), avoiding the dual-i64 promotion
 * failure documented in vm_dualcounter64_loop.
 */
#include <stdio.h>
#include <stdint.h>

enum DiVmPc {
    DI_LOAD       = 0,
    DI_INIT       = 1,
    DI_LOOP_CHECK = 2,
    DI_LOOP_BODY  = 3,
    DI_LOOP_INC   = 4,
    DI_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_deinterleave64_loop_target(uint64_t x) {
    int      idx   = 0;
    uint64_t xx    = 0;
    uint64_t evens = 0;
    uint64_t odds  = 0;
    int      pc    = DI_LOAD;

    while (1) {
        if (pc == DI_LOAD) {
            xx    = x;
            evens = 0ull;
            odds  = 0ull;
            pc = DI_INIT;
        } else if (pc == DI_INIT) {
            idx = 0;
            pc = DI_LOOP_CHECK;
        } else if (pc == DI_LOOP_CHECK) {
            pc = (idx < 32) ? DI_LOOP_BODY : DI_HALT;
        } else if (pc == DI_LOOP_BODY) {
            evens = evens | (((xx >> (2 * idx))     & 1ull) << idx);
            odds  = odds  | (((xx >> (2 * idx + 1)) & 1ull) << idx);
            pc = DI_LOOP_INC;
        } else if (pc == DI_LOOP_INC) {
            idx = idx + 1;
            pc = DI_LOOP_CHECK;
        } else if (pc == DI_HALT) {
            return (odds << 32) | evens;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_deinterleave64(0xAAAAAAAA)=%llu vm_deinterleave64(0x55555555)=%llu\n",
           (unsigned long long)vm_deinterleave64_loop_target(0xAAAAAAAAull),
           (unsigned long long)vm_deinterleave64_loop_target(0x55555555ull));
    return 0;
}
```
