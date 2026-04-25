/* PC-state VM that sums u32 dwords whose value is >= 0x80000000:
 *
 *   n = (x & 1) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     acc = acc + ((d >= 0x80000000) ? d : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_dword_sum_uge_thresh64_loop_target.
 *
 * Predicate-gated value-sum at u32 stride.  Dword-stride counterpart
 * of vm_byte/word_sum_uge_thresh64_loop.
 */
#include <stdio.h>
#include <stdint.h>

enum DcsVmPc {
    DCS_INIT_ALL = 0,
    DCS_CHECK    = 1,
    DCS_BODY     = 2,
    DCS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_sum_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = DCS_INIT_ALL;

    while (1) {
        if (pc == DCS_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = DCS_CHECK;
        } else if (pc == DCS_CHECK) {
            pc = (n > 0ull) ? DCS_BODY : DCS_HALT;
        } else if (pc == DCS_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            acc = acc + ((d >= 0x80000000ull) ? d : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DCS_CHECK;
        } else if (pc == DCS_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_sum_uge_thresh64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_sum_uge_thresh64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
