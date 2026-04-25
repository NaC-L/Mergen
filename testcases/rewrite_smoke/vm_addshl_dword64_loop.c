/* PC-state VM: r = (r + dword) << 1 per iter (add-then-shl chain):
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = (r + (s & 0xFFFFFFFF)) << 1;
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_addshl_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_dword_addchain64_loop (pure ADD, no shift)
 *   - vm_dword_horner7_64_loop (mul *7 then add - mul before add not after)
 *
 * Tests `(r + dword) << 1` add-then-shl-by-1 at dword stride.  Each
 * iter doubles the running sum after adding the next dword chunk.
 */
#include <stdio.h>
#include <stdint.h>

enum AsVmPc {
    AS_INIT_ALL = 0,
    AS_CHECK    = 1,
    AS_BODY     = 2,
    AS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_addshl_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = AS_INIT_ALL;

    while (1) {
        if (pc == AS_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = AS_CHECK;
        } else if (pc == AS_CHECK) {
            pc = (n > 0ull) ? AS_BODY : AS_HALT;
        } else if (pc == AS_BODY) {
            r = (r + (s & 0xFFFFFFFFull)) << 1;
            s = s >> 32;
            n = n - 1ull;
            pc = AS_CHECK;
        } else if (pc == AS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_addshl_dword64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_addshl_dword64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
