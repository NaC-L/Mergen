/* PC-state VM that counts u32 dwords strictly less than 0x40000000:
 *
 *   n = (x & 1) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     cnt = cnt + ((d < 0x40000000) ? 1 : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_dword_lt_thresh_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_lt_thresh_count64_loop (8-bit stride)
 *   - vm_word_lt_thresh_count64_loop (16-bit stride)
 *
 * Tests `icmp ult` + zext + add cmp-counter at 32-bit dword stride.
 * Completes the cmp-counter width matrix for unsigned-less-than.
 */
#include <stdio.h>
#include <stdint.h>

enum DlVmPc {
    DL_INIT_ALL = 0,
    DL_CHECK    = 1,
    DL_BODY     = 2,
    DL_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_lt_thresh_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = DL_INIT_ALL;

    while (1) {
        if (pc == DL_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = DL_CHECK;
        } else if (pc == DL_CHECK) {
            pc = (n > 0ull) ? DL_BODY : DL_HALT;
        } else if (pc == DL_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            cnt = cnt + ((d < 0x40000000ull) ? 1ull : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DL_CHECK;
        } else if (pc == DL_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_lt_thresh_count64(0x12345678)=%llu\n",
           (unsigned long long)vm_dword_lt_thresh_count64_loop_target(0x12345678ull));
    return 0;
}
