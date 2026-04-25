/* PC-state VM that sums bytes whose value is < 0x80:
 *
 *   n = (x & 7) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     acc = acc + ((b < 0x80) ? b : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_byte_sum_ult_thresh64_loop_target.
 *
 * Predicate-gated value-sum, mirror of vm_byte_sum_uge_thresh64_loop
 * with the opposite predicate.
 */
#include <stdio.h>
#include <stdint.h>

enum BcuVmPc {
    BCU_INIT_ALL = 0,
    BCU_CHECK    = 1,
    BCU_BODY     = 2,
    BCU_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_sum_ult_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = BCU_INIT_ALL;

    while (1) {
        if (pc == BCU_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = BCU_CHECK;
        } else if (pc == BCU_CHECK) {
            pc = (n > 0ull) ? BCU_BODY : BCU_HALT;
        } else if (pc == BCU_BODY) {
            uint64_t b = s & 0xFFull;
            acc = acc + ((b < 0x80ull) ? b : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BCU_CHECK;
        } else if (pc == BCU_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_sum_ult_thresh64(0x7F7F7F7F7F7F7F7F)=%llu\n",
           (unsigned long long)vm_byte_sum_ult_thresh64_loop_target(0x7F7F7F7F7F7F7F7Full));
    return 0;
}
