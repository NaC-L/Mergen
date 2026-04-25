# vm_bytematch64_loop - original vs lifted equivalence

- **Verdict:** PASS
- **Cases:** 10/10 equivalent
- **Source:** `testcases/rewrite_smoke/vm_bytematch64_loop.c`
- **Lifted IR:** `rewrite-regression-work/ir_outputs/vm_bytematch64_loop.ll`
- **Symbol:** `vm_bytematch64_loop_target`
- **Native driver:** `rewrite-regression-work/eq/vm_bytematch64_loop_eq.exe`
- **Lifted signature:** `define i64 @main(i64 %RAX, i64 %RCX, i64 %RDX, i64 %RBX, i64 %RSP, i64 %RBP, i64 %RSI, i64 %RDI, i64 %R8, i64 %R9, i64 %R10, i64 %R11, i64 %R12, i64 %R13, i64 %R14, i64 %R15, ptr nocapture readnone %EIP, ptr nocapture readnone %memory, i128 %XMM0, i128 %XMM1, i128 %XMM2, i128 %XMM3, i128 %XMM4, i128 %XMM5, i128 %XMM6, i128 %XMM7, i128 %XMM8, i128 %XMM9, i128 %XMM10, i128 %XMM11, i128 %XMM12, i128 %XMM13, i128 %XMM14, i128 %XMM15) local_unnamed_addr #0`

## Equivalence (native vs lifted)

Each row runs the same inputs through (a) the original program compiled to a real Win64 binary that calls `vm_bytematch64_loop_target` directly, and (b) the lifted+optimized LLVM IR executed via `lli`. A case is equivalent only if both observations agree and also match the manifest's expected value.

| # | Inputs | Manifest | Native | Lifted | Equivalent | Label |
|---|--------|----------|--------|--------|------------|-------|
| 1 | RCX=0 | 7 | 7 | 7 | yes | x=0: target=0, all 7 lower bytes match |
| 2 | RCX=72340172838076673 | 7 | 7 | 7 | yes | 0x0101...01: target=1, all match |
| 3 | RCX=18374686479671623680 | 0 | 0 | 0 | yes | 0xFF00...00: target=0xFF, none match |
| 4 | RCX=18446744073709551615 | 7 | 7 | 7 | yes | max u64: target=0xFF, all match |
| 5 | RCX=3405691582 | 3 | 3 | 3 | yes | 0xCAFEBABE: target=0, lower 3 bytes are 0 |
| 6 | RCX=14627333941892939776 | 0 | 0 | 0 | yes | 0xCAFE000000000000: target=0xCA, none match |
| 7 | RCX=1302123111085380351 | 6 | 6 | 6 | yes | 0x12121212121212FF: target=0x12, 6 match |
| 8 | RCX=12249988016147062528 | 0 | 0 | 0 | yes | 0xAA00BB00CC00DD00: target=0xAA, none |
| 9 | RCX=18399425019007729919 | 1 | 1 | 1 | yes | 0xFF5555555555AAFF: target=0xFF, 1 match (low) |
| 10 | RCX=11400714819323198485 | 0 | 0 | 0 | yes | K (golden): target=0x9E, none match |

## Source

```c
/* PC-state VM that counts how many of the lower 7 bytes of x equal the
 * top byte of x.
 *   target = (x >> 56) & 0xFF;
 *   count = 0;
 *   for i in 0..7:
 *     byte = (x >> (i*8)) & 0xFF
 *     if byte == target: count++
 *   return count;
 * 7-trip fixed loop with byte-walking shift + byte-equality compare.
 * Lift target: vm_bytematch64_loop_target.
 *
 * Distinct from vm_xorbytes64_loop (XOR-fold) and vm_djb264_loop
 * (multiplicative hash): byte-equality count via icmp eq i64 (after
 * masking) inside a fixed loop with input-derived target byte.
 */
#include <stdio.h>
#include <stdint.h>

enum BmVmPc {
    BM_LOAD       = 0,
    BM_INIT       = 1,
    BM_LOOP_CHECK = 2,
    BM_LOOP_BODY  = 3,
    BM_LOOP_INC   = 4,
    BM_HALT       = 5,
};

__declspec(noinline)
int vm_bytematch64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t target = 0;
    int      count  = 0;
    int      pc     = BM_LOAD;

    while (1) {
        if (pc == BM_LOAD) {
            xx     = x;
            target = (x >> 56) & 0xFFull;
            count  = 0;
            pc = BM_INIT;
        } else if (pc == BM_INIT) {
            idx = 0;
            pc = BM_LOOP_CHECK;
        } else if (pc == BM_LOOP_CHECK) {
            pc = (idx < 7) ? BM_LOOP_BODY : BM_HALT;
        } else if (pc == BM_LOOP_BODY) {
            uint64_t b = (xx >> (idx * 8)) & 0xFFull;
            if (b == target) {
                count = count + 1;
            }
            pc = BM_LOOP_INC;
        } else if (pc == BM_LOOP_INC) {
            idx = idx + 1;
            pc = BM_LOOP_CHECK;
        } else if (pc == BM_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_bytematch64(0x0101010101010101)=%d vm_bytematch64(0xCAFEBABE)=%d\n",
           vm_bytematch64_loop_target(0x0101010101010101ull),
           vm_bytematch64_loop_target(0xCAFEBABEull));
    return 0;
}
```
