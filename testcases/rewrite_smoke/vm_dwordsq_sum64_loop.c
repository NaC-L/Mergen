/* PC-state VM that sums squared u32 dwords over n = (x & 1) + 1 iters:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     r = r + d * d;          // u32 squared, ADD-folded
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dwordsq_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_wordsq_sum64_loop   (16-bit stride)
 *   - vm_bytesq_sum64_loop   (8-bit stride)
 *   - vm_dword_xormul64_loop (per-dword self-multiply but XOR-folded)
 *
 * Tests u32 self-multiply (d * d) accumulator at u32 stride with ADD
 * fold.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DqVmPc {
    DQ_INIT_ALL = 0,
    DQ_CHECK    = 1,
    DQ_BODY     = 2,
    DQ_INC      = 3,
    DQ_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dwordsq_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DQ_INIT_ALL;

    while (1) {
        if (pc == DQ_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DQ_CHECK;
        } else if (pc == DQ_CHECK) {
            pc = (i < n) ? DQ_BODY : DQ_HALT;
        } else if (pc == DQ_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            r = r + d * d;
            s = s >> 32;
            pc = DQ_INC;
        } else if (pc == DQ_INC) {
            i = i + 1ull;
            pc = DQ_CHECK;
        } else if (pc == DQ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dwordsq_sum64(0x100000003)=%llu\n",
           (unsigned long long)vm_dwordsq_sum64_loop_target(0x100000003ull));
    return 0;
}
