/* PC-state VM: r = (r + byte) << 1 per iter (add-then-shl chain):
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = (r + (s & 0xFF)) << 1;
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_addshl_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_addshl_dword64_loop  (32-bit dword stride)
 *   - vm_byte_addchain64_loop (pure ADD, no shift)
 *
 * Tests `(r + byte) << 1` add-then-shl-by-1 at byte stride.  Each iter
 * doubles the running sum after adding the next byte chunk.
 */
#include <stdio.h>
#include <stdint.h>

enum AsbVmPc {
    ASB_INIT_ALL = 0,
    ASB_CHECK    = 1,
    ASB_BODY     = 2,
    ASB_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_addshl_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = ASB_INIT_ALL;

    while (1) {
        if (pc == ASB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            pc = ASB_CHECK;
        } else if (pc == ASB_CHECK) {
            pc = (n > 0ull) ? ASB_BODY : ASB_HALT;
        } else if (pc == ASB_BODY) {
            r = (r + (s & 0xFFull)) << 1;
            s = s >> 8;
            n = n - 1ull;
            pc = ASB_CHECK;
        } else if (pc == ASB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_addshl_byte64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_addshl_byte64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
