/* PC-state VM running the Euclidean GCD on full uint64_t values.
 *   while (b) { t = b; b = a % b; a = t; }
 *   return a;
 * Inputs: a in RCX, b in RDX (both full 64-bit).
 * Lift target: vm_gcd64_loop_target.
 *
 * Distinct from vm_gcd_loop (i32 GCD): exercises i64 urem in a
 * data-dependent loop with both operands at full width.
 */
#include <stdio.h>
#include <stdint.h>

enum G64VmPc {
    G64_LOAD       = 0,
    G64_LOOP_CHECK = 1,
    G64_LOOP_BODY  = 2,
    G64_HALT       = 3,
};

__declspec(noinline)
uint64_t vm_gcd64_loop_target(uint64_t x, uint64_t y) {
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t t  = 0;
    int      pc = G64_LOAD;

    while (1) {
        if (pc == G64_LOAD) {
            a = x;
            b = y;
            pc = G64_LOOP_CHECK;
        } else if (pc == G64_LOOP_CHECK) {
            pc = (b != 0ull) ? G64_LOOP_BODY : G64_HALT;
        } else if (pc == G64_LOOP_BODY) {
            t = b;
            b = a % b;
            a = t;
            pc = G64_LOOP_CHECK;
        } else if (pc == G64_HALT) {
            return a;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_gcd64(12,18)=%llu vm_gcd64(0xCAFEBABE,0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_gcd64_loop_target(12ull, 18ull),
           (unsigned long long)vm_gcd64_loop_target(0xCAFEBABEull, 0xDEADBEEFull));
    return 0;
}
