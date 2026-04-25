/* PC-state VM that sums u32 dwords whose value is < 0x80000000:
 *
 *   n = (x & 1) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     acc = acc + ((d < 0x80000000) ? d : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_dword_sum_ult_thresh64_loop_target.
 *
 * Predicate-gated value-sum at u32 stride, mirror predicate of
 * vm_dword_sum_uge_thresh64_loop.  Completes the ult value-sum at
 * all 3 widths.
 */
#include <stdio.h>
#include <stdint.h>

enum DcuVmPc {
    DCU_INIT_ALL = 0,
    DCU_CHECK    = 1,
    DCU_BODY     = 2,
    DCU_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_sum_ult_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = DCU_INIT_ALL;

    while (1) {
        if (pc == DCU_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = DCU_CHECK;
        } else if (pc == DCU_CHECK) {
            pc = (n > 0ull) ? DCU_BODY : DCU_HALT;
        } else if (pc == DCU_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            acc = acc + ((d < 0x80000000ull) ? d : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DCU_CHECK;
        } else if (pc == DCU_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_sum_ult_thresh64(0x7FFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_sum_ult_thresh64_loop_target(0x7FFFFFFFull));
    return 0;
}
