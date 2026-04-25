/* PC-state VM that XOR-accumulates bytes whose value is >= 0x80:
 *
 *   n = (x & 7) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     acc = acc ^ ((b >= 0x80) ? b : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_byte_xor_uge_thresh64_loop_target.
 *
 * Predicate-gated XOR accumulator at byte stride.  Distinct from
 * vm_byte_sum_uge_thresh64_loop because the reducer is xor, not add.
 * Tests that the lifter folds select+xor identically to select+add.
 */
#include <stdio.h>
#include <stdint.h>

enum BxsVmPc {
    BXS_INIT_ALL = 0,
    BXS_CHECK    = 1,
    BXS_BODY     = 2,
    BXS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_xor_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = BXS_INIT_ALL;

    while (1) {
        if (pc == BXS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = BXS_CHECK;
        } else if (pc == BXS_CHECK) {
            pc = (n > 0ull) ? BXS_BODY : BXS_HALT;
        } else if (pc == BXS_BODY) {
            uint64_t b = s & 0xFFull;
            acc = acc ^ ((b >= 0x80ull) ? b : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BXS_CHECK;
        } else if (pc == BXS_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_xor_uge_thresh64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_xor_uge_thresh64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
