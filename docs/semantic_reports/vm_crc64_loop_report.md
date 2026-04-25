# vm_crc64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_crc64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_crc64_loop.ll`
- **Symbol:** `vm_crc64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_crc64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_crc64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 14514072000185962306 | 14514072000185962306 | 14514072000185962306 | yes | x=0: crc init=1, n=1, single CRC step |
| 2 | RCX=1 | 7257036000092981153 | 7257036000092981153 | 7257036000092981153 | yes | x=1, n=2 |
| 3 | RCX=7 | 4357999468653093127 | 4357999468653093127 | 4357999468653093127 | yes | x=7, n=8 max |
| 4 | RCX=255 | 16189773752444600153 | 16189773752444600153 | 16189773752444600153 | yes | x=0xFF, n=8 |
| 5 | RCX=51966 | 6017914993561854371 | 6017914993561854371 | 6017914993561854371 | yes | 0xCAFE, n=7 |
| 6 | RCX=3405691582 | 11164346891378004481 | 11164346891378004481 | 11164346891378004481 | yes | 0xCAFEBABE, n=7 |
| 7 | RCX=1311768467463790320 | 13868409170423275578 | 13868409170423275578 | 13868409170423275578 | yes | 0x123...DEF0, n=1 |
| 8 | RCX=18446744073709551615 | 16164085970585043110 | 16164085970585043110 | 16164085970585043110 | yes | max u64, n=8 |
| 9 | RCX=11400714819323198485 | 6955128548432713259 | 6955128548432713259 | 6955128548432713259 | yes | K (golden), n=6 |
| 10 | RCX=3735928559 | 11328242235717907630 | 11328242235717907630 | 11328242235717907630 | yes | 0xDEADBEEF, n=8 |

## Source

```c
/* PC-state VM running an i64 CRC-64-style polynomial reduction step.
 *   crc = x | 1;
 *   for i in 0..n:
 *     if (crc & 1): crc = (crc >> 1) ^ POLY
 *     else:         crc = (crc >> 1)
 * Variable trip n = (x & 7) + 1.  POLY = 0xC96C5795D7870F42 (CRC-64 ISO).
 * Lift target: vm_crc64_loop_target.
 *
 * Distinct from vm_lfsr64_loop (4-tap feedback) and vm_pcg64_loop
 * (LCG step): single-tap conditional XOR gated by LSB, classic CRC
 * polynomial reduction shape.
 */
#include <stdio.h>
#include <stdint.h>

enum CrVmPc {
    CR_LOAD       = 0,
    CR_INIT       = 1,
    CR_LOOP_CHECK = 2,
    CR_LOOP_BODY  = 3,
    CR_LOOP_INC   = 4,
    CR_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_crc64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t crc = 0;
    int      pc  = CR_LOAD;

    while (1) {
        if (pc == CR_LOAD) {
            crc = x | 1ull;
            n   = (int)(x & 7ull) + 1;
            pc = CR_INIT;
        } else if (pc == CR_INIT) {
            idx = 0;
            pc = CR_LOOP_CHECK;
        } else if (pc == CR_LOOP_CHECK) {
            pc = (idx < n) ? CR_LOOP_BODY : CR_HALT;
        } else if (pc == CR_LOOP_BODY) {
            if ((crc & 1ull) != 0ull) {
                crc = (crc >> 1) ^ 0xC96C5795D7870F42ull;
            } else {
                crc = crc >> 1;
            }
            pc = CR_LOOP_INC;
        } else if (pc == CR_LOOP_INC) {
            idx = idx + 1;
            pc = CR_LOOP_CHECK;
        } else if (pc == CR_HALT) {
            return crc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_crc64(0xCAFE)=%llu vm_crc64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_crc64_loop_target(0xCAFEull),
           (unsigned long long)vm_crc64_loop_target(0xDEADBEEFull));
    return 0;
}
```
