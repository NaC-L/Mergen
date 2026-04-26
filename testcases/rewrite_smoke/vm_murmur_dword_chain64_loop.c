/* PC-state VM: dword-windowed Murmur-style mix with fold inside loop:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = (r ^ (s & 0xFFFFFFFF)) * 0xC6A4A7935BD1E995;
 *     r = r ^ (r >> 47);
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_murmur_dword_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_murmur_word_chain64_loop  (16-bit stride)
 *   - vm_murmur_byte_chain64_loop  (8-bit stride)
 *   - vm_dword_xormul64_loop       (per-lane self-multiply, no fold)
 *
 * Tests u32 dword-windowed Murmur-style mix at u32 stride.  Trip count
 * <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum MdVmPc {
    MD_INIT_ALL = 0,
    MD_CHECK    = 1,
    MD_BODY     = 2,
    MD_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_murmur_dword_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = MD_INIT_ALL;

    while (1) {
        if (pc == MD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = MD_CHECK;
        } else if (pc == MD_CHECK) {
            pc = (n > 0ull) ? MD_BODY : MD_HALT;
        } else if (pc == MD_BODY) {
            r = (r ^ (s & 0xFFFFFFFFull)) * 0xC6A4A7935BD1E995ull;
            r = r ^ (r >> 47);
            s = s >> 32;
            n = n - 1ull;
            pc = MD_CHECK;
        } else if (pc == MD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_murmur_dword_chain64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_murmur_dword_chain64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
