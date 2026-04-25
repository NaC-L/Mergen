/* PC-state VM running the parallel-prefix-XOR step iteratively on full
 * uint64_t.  Each iteration applies r = r ^ (r >> 1).
 * Variable trip n = (x & 7) + 1.
 *
 * One iteration computes Gray-code-style bit-pair XOR; repeating it n
 * times is a self-cancelling sequence that diverges from input by a
 * different bit pattern at each trip count.
 *
 * Lift target: vm_xorshrink64_loop_target.
 *
 * Distinct from vm_crc64_loop (gated XOR with poly), vm_lfsr64_loop
 * (shift+or with high-bit feed), and vm_xorshift64_loop (3-step
 * shift+xor): pure shift-by-1 + XOR repeated, no conditional, no other
 * shifts.  Lifter likely keeps explicit lshr+xor pair per iteration.
 */
#include <stdio.h>
#include <stdint.h>

enum XkVmPc {
    XK_LOAD       = 0,
    XK_INIT       = 1,
    XK_LOOP_CHECK = 2,
    XK_LOOP_BODY  = 3,
    XK_LOOP_INC   = 4,
    XK_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_xorshrink64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t r   = 0;
    int      pc  = XK_LOAD;

    while (1) {
        if (pc == XK_LOAD) {
            r = x;
            n = (int)(x & 7ull) + 1;
            pc = XK_INIT;
        } else if (pc == XK_INIT) {
            idx = 0;
            pc = XK_LOOP_CHECK;
        } else if (pc == XK_LOOP_CHECK) {
            pc = (idx < n) ? XK_LOOP_BODY : XK_HALT;
        } else if (pc == XK_LOOP_BODY) {
            r = r ^ (r >> 1);
            pc = XK_LOOP_INC;
        } else if (pc == XK_LOOP_INC) {
            idx = idx + 1;
            pc = XK_LOOP_CHECK;
        } else if (pc == XK_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorshrink64(0xCAFE)=0x%llx vm_xorshrink64(0xCAFEBABE)=0x%llx\n",
           (unsigned long long)vm_xorshrink64_loop_target(0xCAFEull),
           (unsigned long long)vm_xorshrink64_loop_target(0xCAFEBABEull));
    return 0;
}
