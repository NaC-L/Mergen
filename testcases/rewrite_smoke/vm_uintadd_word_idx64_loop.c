/* PC-state VM that ADDs unsigned-u16 * counter into the accumulator
 * over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + (s & 0xFFFF) * (i + 1);   // u16 zext * counter, ADD-folded
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_uintadd_word_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_uintadd_byte_idx64_loop  (8-bit lane stride)
 *   - vm_xormul_word_idx64_loop   (XOR-folded counterpart at u16 stride)
 *
 * Tests unsigned word (zext-i16) * counter ADD-folded into an i64
 * accumulator at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum UawVmPc {
    UAW_INIT_ALL = 0,
    UAW_CHECK    = 1,
    UAW_BODY     = 2,
    UAW_INC      = 3,
    UAW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_uintadd_word_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = UAW_INIT_ALL;

    while (1) {
        if (pc == UAW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = UAW_CHECK;
        } else if (pc == UAW_CHECK) {
            pc = (i < n) ? UAW_BODY : UAW_HALT;
        } else if (pc == UAW_BODY) {
            r = r + (s & 0xFFFFull) * (i + 1ull);
            s = s >> 16;
            pc = UAW_INC;
        } else if (pc == UAW_INC) {
            i = i + 1ull;
            pc = UAW_CHECK;
        } else if (pc == UAW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_uintadd_word_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_uintadd_word_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
