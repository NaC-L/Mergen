# vm_threestate_xormul64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_threestate_xormul64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_threestate_xormul64_loop.ll`
- **Symbol:** `vm_threestate_xormul64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_threestate_xormul64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_threestate_xormul64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 11400714819323198484 | 11400714819323198484 | 11400714819323198484 | yes | x=0 a=0 b=~0 c=0 n=1 |
| 2 | RCX=1 | 1995974887614534114 | 1995974887614534114 | 1995974887614534114 | yes | x=1 n=2 |
| 3 | RCX=2 | 17689537465226585472 | 17689537465226585472 | 17689537465226585472 | yes | x=2 n=3 |
| 4 | RCX=7 | 10648103815310885736 | 10648103815310885736 | 10648103815310885736 | yes | x=7 n=8: max trip |
| 5 | RCX=8 | 8037997838901812412 | 8037997838901812412 | 8037997838901812412 | yes | x=8 n=1: single iter |
| 6 | RCX=3405691582 | 7095180427346219998 | 7095180427346219998 | 7095180427346219998 | yes | 0xCAFEBABE: n=7 |
| 7 | RCX=3735928559 | 15430819088305965056 | 15430819088305965056 | 15430819088305965056 | yes | 0xDEADBEEF: n=8 |
| 8 | RCX=18446744073709551615 | 17898289560204304 | 17898289560204304 | 17898289560204304 | yes | all 0xFF: a=~0 b=0 c=-GR |
| 9 | RCX=72623859790382856 | 5158310972223453116 | 5158310972223453116 | 5158310972223453116 | yes | 0x0102...0708: n=1 single iter |
| 10 | RCX=1311768467463790320 | 7738869930969336900 | 7738869930969336900 | 7738869930969336900 | yes | 0x12345...EF0: n=1 |

## Source

```c
/* PC-state VM running a three-state cross-feeding recurrence over n iters:
 *
 *   n = (x & 7) + 1;
 *   a = x; b = ~x; c = x * GR;
 *   for (i = 0; i < n; i++) {
 *     t = a ^ b;
 *     a = b;
 *     b = c + 1;
 *     c = t * GR + a;     // GR = 0x9E3779B97F4A7C15
 *   }
 *   return a ^ b ^ c;
 *
 * Lift target: vm_threestate_xormul64_loop_target.
 *
 * Distinct from:
 *   - vm_tribonacci64_loop  (additive a,b,c -> b,c,a+b+c)
 *   - vm_pairmix64_loop     (two-state cross-feed with temp barrier)
 *   - vm_xs64star / vm_splitmix64 (single-state PRNGs)
 *
 * Three i64 slots all updated each iteration with sequential reads
 * captured into temp `t` before any writeback (TEA-bug workaround).
 * Body mixes xor (t), increment (b'), multiply-by-GR + add (c').
 * Returns combined a^b^c at the end.
 */
#include <stdio.h>
#include <stdint.h>

enum TsVmPc {
    TS_INIT_ALL = 0,
    TS_CHECK    = 1,
    TS_BODY     = 2,
    TS_INC      = 3,
    TS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_threestate_xormul64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t c  = 0;
    uint64_t i  = 0;
    int      pc = TS_INIT_ALL;

    while (1) {
        if (pc == TS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = x;
            b = ~x;
            c = x * 0x9E3779B97F4A7C15ull;
            i = 0ull;
            pc = TS_CHECK;
        } else if (pc == TS_CHECK) {
            pc = (i < n) ? TS_BODY : TS_HALT;
        } else if (pc == TS_BODY) {
            uint64_t t = a ^ b;
            a = b;
            b = c + 1ull;
            c = t * 0x9E3779B97F4A7C15ull + a;
            pc = TS_INC;
        } else if (pc == TS_INC) {
            i = i + 1ull;
            pc = TS_CHECK;
        } else if (pc == TS_HALT) {
            return a ^ b ^ c;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_threestate_xormul64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_threestate_xormul64_loop_target(0xCAFEBABEull));
    return 0;
}
```
