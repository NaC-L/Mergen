/* PC-state VM tracking u32 dword min/max range over n=(x&1)+1 iters:
 *
 *   n = (x & 1) + 1;
 *   s = x; mn = 0xFFFFFFFF; mx = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     if (d > mx) mx = d;
 *     if (d < mn) mn = d;
 *     s >>= 32;
 *     n--;
 *   }
 *   return mx - mn;
 *
 * Lift target: vm_dword_range64_loop_target.
 *
 * Distinct from:
 *   - vm_byterange64_loop  (u8 byte stride)
 *   - vm_word_range64_loop (u16 word stride)
 *
 * Tests umax/umin folds at 32-bit dword stride.  Single-dword inputs
 * always return 0 (mx=mn=dword).  4 stateful slots (n,s,mn,mx) with
 * n-decrement loop control.
 */
#include <stdio.h>
#include <stdint.h>

enum DrVmPc {
    DR_INIT_ALL = 0,
    DR_CHECK    = 1,
    DR_BODY     = 2,
    DR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_range64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t mn = 0;
    uint64_t mx = 0;
    int      pc = DR_INIT_ALL;

    while (1) {
        if (pc == DR_INIT_ALL) {
            n  = (x & 1ull) + 1ull;
            s  = x;
            mn = 0xFFFFFFFFull;
            mx = 0ull;
            pc = DR_CHECK;
        } else if (pc == DR_CHECK) {
            pc = (n > 0ull) ? DR_BODY : DR_HALT;
        } else if (pc == DR_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            mx = (d > mx) ? d : mx;
            mn = (d < mn) ? d : mn;
            s = s >> 32;
            n = n - 1ull;
            pc = DR_CHECK;
        } else if (pc == DR_HALT) {
            return mx - mn;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_range64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_dword_range64_loop_target(0xDEADBEEFull));
    return 0;
}
