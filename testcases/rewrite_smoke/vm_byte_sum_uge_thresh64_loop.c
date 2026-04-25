/* PC-state VM that sums bytes whose value is >= 0x80:
 *
 *   n = (x & 7) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     acc = acc + ((b >= 0x80) ? b : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_byte_sum_uge_thresh64_loop_target.
 *
 * Distinct from cmp-counter samples: instead of counting matches,
 * accumulates the matching byte value itself.  Tests a select-then-add
 * (predicate-gated accumulator) shape rather than a zext-then-add.
 */
#include <stdio.h>
#include <stdint.h>

enum BcsVmPc {
    BCS_INIT_ALL = 0,
    BCS_CHECK    = 1,
    BCS_BODY     = 2,
    BCS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_sum_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = BCS_INIT_ALL;

    while (1) {
        if (pc == BCS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = BCS_CHECK;
        } else if (pc == BCS_CHECK) {
            pc = (n > 0ull) ? BCS_BODY : BCS_HALT;
        } else if (pc == BCS_BODY) {
            uint64_t b = s & 0xFFull;
            acc = acc + ((b >= 0x80ull) ? b : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BCS_CHECK;
        } else if (pc == BCS_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_sum_uge_thresh64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_sum_uge_thresh64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
