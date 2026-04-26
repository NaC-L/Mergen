/* PC-state VM that ORs (u32 dword OR counter) into the accumulator
 * over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r | ((s & 0xFFFFFFFF) | (i + 1));   // dword OR counter, OR-folded
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_orsum_dword_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_orsum_word_idx64_loop   (16-bit lane stride)
 *   - vm_orsum_byte_idx64_loop   (8-bit lane stride)
 *   - vm_andsum_dword_idx64_loop (AND-folded counterpart at u32 stride)
 *
 * Tests (lane | counter) chained through OR fold at u32 stride.  Trip
 * count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum OsdVmPc {
    OSD_INIT_ALL = 0,
    OSD_CHECK    = 1,
    OSD_BODY     = 2,
    OSD_INC      = 3,
    OSD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_orsum_dword_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = OSD_INIT_ALL;

    while (1) {
        if (pc == OSD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = OSD_CHECK;
        } else if (pc == OSD_CHECK) {
            pc = (i < n) ? OSD_BODY : OSD_HALT;
        } else if (pc == OSD_BODY) {
            r = r | ((s & 0xFFFFFFFFull) | (i + 1ull));
            s = s >> 32;
            pc = OSD_INC;
        } else if (pc == OSD_INC) {
            i = i + 1ull;
            pc = OSD_CHECK;
        } else if (pc == OSD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_orsum_dword_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_orsum_dword_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
