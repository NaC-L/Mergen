# vm_prefixxor64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_prefixxor64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_prefixxor64_loop.ll`
- **Symbol:** `vm_prefixxor64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_prefixxor64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_prefixxor64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 0 | 0 | 0 | yes | x=0 |
| 2 | RCX=1 | 72340172838076673 | 72340172838076673 | 72340172838076673 | yes | x=1: prefix-xor propagates 0x01 through all 8 bytes -> 0x0101010101010101 |
| 3 | RCX=255 | 18446744073709551615 | 18446744073709551615 | 18446744073709551615 | yes | x=0xFF: 0xFF in all bytes |
| 4 | RCX=72623859790382856 | 579006156283383560 | 579006156283383560 | 579006156283383560 | yes | x=0x0102...0708 known-trace |
| 5 | RCX=3405691582 | 3472328296240907454 | 3472328296240907454 | 3472328296240907454 | yes | x=0xCAFEBABE |
| 6 | RCX=1311768467463790320 | 5108812202782448 | 5108812202782448 | 5108812202782448 | yes | 0x123456789ABCDEF0 |
| 7 | RCX=18446744073709551615 | 71777214294589695 | 71777214294589695 | 71777214294589695 | yes | max u64: alternating prefix |
| 8 | RCX=11400714819323198485 | 3867357213934971157 | 3867357213934971157 | 3867357213934971157 | yes | K (golden) |
| 9 | RCX=51966 | 3761688987579987198 | 3761688987579987198 | 3761688987579987198 | yes | x=0xCAFE |
| 10 | RCX=12249977906276641280 | 48037663028718080 | 48037663028718080 | 48037663028718080 | yes | 0xAA00AA00AA00AA00 |

## Source

```c
/* PC-state VM that computes a byte-wise PREFIX-XOR scan on the bytes of
 * x and packs the running results back into a uint64_t.
 *   result = 0; acc = 0;
 *   for i in 0..8:
 *     byte = (x >> (i*8)) & 0xFF
 *     acc ^= byte
 *     result |= (acc << (i*8))
 *   return result;
 * 8-trip fixed loop with byte-walking shift on both the input and the
 * pack side.  Lift target: vm_prefixxor64_loop_target.
 *
 * Distinct from vm_xorbytes64_loop (reduces to single byte) and
 * vm_djb264_loop (multiplicative byte hash): produces an 8-byte packed
 * running-XOR scan; tests two simultaneous byte-walking shifts (one
 * load, one store-by-or) inside a single loop body.
 */
#include <stdio.h>
#include <stdint.h>

enum PfVmPc {
    PF_LOAD       = 0,
    PF_INIT       = 1,
    PF_LOOP_CHECK = 2,
    PF_LOOP_BODY  = 3,
    PF_LOOP_INC   = 4,
    PF_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_prefixxor64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t acc    = 0;
    uint64_t result = 0;
    int      pc     = PF_LOAD;

    while (1) {
        if (pc == PF_LOAD) {
            xx     = x;
            acc    = 0ull;
            result = 0ull;
            pc = PF_INIT;
        } else if (pc == PF_INIT) {
            idx = 0;
            pc = PF_LOOP_CHECK;
        } else if (pc == PF_LOOP_CHECK) {
            pc = (idx < 8) ? PF_LOOP_BODY : PF_HALT;
        } else if (pc == PF_LOOP_BODY) {
            uint64_t b = (xx >> (idx * 8)) & 0xFFull;
            acc = acc ^ b;
            result = result | (acc << (idx * 8));
            pc = PF_LOOP_INC;
        } else if (pc == PF_LOOP_INC) {
            idx = idx + 1;
            pc = PF_LOOP_CHECK;
        } else if (pc == PF_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_prefixxor64(0xCAFEBABE)=%llu vm_prefixxor64(max)=%llu\n",
           (unsigned long long)vm_prefixxor64_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_prefixxor64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
```
