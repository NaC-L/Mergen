/* PC-state VM that runs Horner-style hash on u32 dwords with mul 7:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r * 7 + (s & 0xFFFFFFFF);
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_horner7_64_loop_target.
 *
 * Distinct from:
 *   - vm_word_horner13_64_loop (Horner on u16 words with mul 13)
 *   - vm_mul3byte_chain64_loop (Horner on bytes with mul 3)
 *   - vm_djb264_loop          (Horner on bytes with mul 33)
 *
 * Tests Horner mul-then-add chain with multiplier 7 at 32-bit dword
 * stride.  Different stride width AND different multiplier than
 * existing Horner samples.
 */
#include <stdio.h>
#include <stdint.h>

enum DhVmPc {
    DH_INIT_ALL = 0,
    DH_CHECK    = 1,
    DH_BODY     = 2,
    DH_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_horner7_64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = DH_INIT_ALL;

    while (1) {
        if (pc == DH_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = DH_CHECK;
        } else if (pc == DH_CHECK) {
            pc = (n > 0ull) ? DH_BODY : DH_HALT;
        } else if (pc == DH_BODY) {
            r = r * 7ull + (s & 0xFFFFFFFFull);
            s = s >> 32;
            n = n - 1ull;
            pc = DH_CHECK;
        } else if (pc == DH_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_horner7_64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_horner7_64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
