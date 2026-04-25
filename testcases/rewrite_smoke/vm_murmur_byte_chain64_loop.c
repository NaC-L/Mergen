/* PC-state VM: byte-windowed Murmur-style mix with fold inside loop:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = (r ^ (s & 0xFF)) * 0xC6A4A7935BD1E995;   // Murmur magic
 *     r = r ^ (r >> 47);                            // fold inside body
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_murmur_byte_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_xxhmix64_loop      (byte-windowed, DIFFERENT magic, fold OUTSIDE loop)
 *   - vm_murmurstep64_loop  (uses x not byte-windowed; fold inside)
 *   - vm_fnv1a64_loop       (different magic; no fold)
 *
 * Tests byte-windowed Murmur-style mix with the lshr-47 fold inside
 * the loop body (not outside).  Combines byte stream + 64-bit Murmur
 * magic + per-iter fold.
 */
#include <stdio.h>
#include <stdint.h>

enum MbVmPc {
    MB_INIT_ALL = 0,
    MB_CHECK    = 1,
    MB_BODY     = 2,
    MB_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_murmur_byte_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = MB_INIT_ALL;

    while (1) {
        if (pc == MB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            pc = MB_CHECK;
        } else if (pc == MB_CHECK) {
            pc = (n > 0ull) ? MB_BODY : MB_HALT;
        } else if (pc == MB_BODY) {
            r = (r ^ (s & 0xFFull)) * 0xC6A4A7935BD1E995ull;
            r = r ^ (r >> 47);
            s = s >> 8;
            n = n - 1ull;
            pc = MB_CHECK;
        } else if (pc == MB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_murmur_byte_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_murmur_byte_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
