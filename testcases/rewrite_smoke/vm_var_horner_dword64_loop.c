/* PC-state VM: variable Horner over u32 dwords with multiplier from
 * loop counter:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r * (n + 1) + (s & 0xFFFFFFFF);
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_var_horner_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_var_horner_word64_loop (16-bit stride)
 *   - vm_var_horner64_loop      (8-bit stride)
 *   - vm_dword_horner7_64_loop  (constant multiplier 7)
 *
 * Tests Horner-style chain at u32 stride where the multiplier is the
 * LOOP COUNTER (n+1).  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum VhdVmPc {
    VHD_INIT_ALL = 0,
    VHD_CHECK    = 1,
    VHD_BODY     = 2,
    VHD_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_var_horner_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = VHD_INIT_ALL;

    while (1) {
        if (pc == VHD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = VHD_CHECK;
        } else if (pc == VHD_CHECK) {
            pc = (n > 0ull) ? VHD_BODY : VHD_HALT;
        } else if (pc == VHD_BODY) {
            r = r * (n + 1ull) + (s & 0xFFFFFFFFull);
            s = s >> 32;
            n = n - 1ull;
            pc = VHD_CHECK;
        } else if (pc == VHD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_var_horner_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_var_horner_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
