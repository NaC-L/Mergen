/* PC-state VM: word-windowed Murmur-style mix with fold inside loop:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = (r ^ (s & 0xFFFF)) * 0xC6A4A7935BD1E995;   // Murmur magic
 *     r = r ^ (r >> 47);                              // fold inside body
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_murmur_word_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_murmur_byte_chain64_loop  (8-bit stride)
 *   - vm_word_xormul64_loop        (per-lane self-multiply, no fold)
 *
 * Tests u16 word-windowed Murmur-style mix with the lshr-47 fold inside
 * the loop body at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum MwVmPc {
    MW_INIT_ALL = 0,
    MW_CHECK    = 1,
    MW_BODY     = 2,
    MW_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_murmur_word_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = MW_INIT_ALL;

    while (1) {
        if (pc == MW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = MW_CHECK;
        } else if (pc == MW_CHECK) {
            pc = (n > 0ull) ? MW_BODY : MW_HALT;
        } else if (pc == MW_BODY) {
            r = (r ^ (s & 0xFFFFull)) * 0xC6A4A7935BD1E995ull;
            r = r ^ (r >> 47);
            s = s >> 16;
            n = n - 1ull;
            pc = MW_CHECK;
        } else if (pc == MW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_murmur_word_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_murmur_word_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
