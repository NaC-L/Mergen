/* PC-state VM that runs a two-state AND/XOR-mul cross-feed:
 *
 *   n = (x & 7) + 1;
 *   a = ~0; b = x;
 *   for (i = 0; i < n; i++) {
 *     uint64_t t = a;
 *     a = a & b;
 *     b = t ^ (b * 7);
 *   }
 *   return a + b;
 *
 * Lift target: vm_andxor_pair64_loop_target.
 *
 * Distinct from:
 *   - vm_orxor_pair64_loop (sister: OR instead of AND, different init)
 *   - vm_pairmix64_loop    (add+mul-by-GR cross-feed)
 *
 * Tests an explicit temp barrier (`t = a`) so the AND (`a &= b`) and
 * XOR-mul (`b = t ^ b*7`) updates both see the original a before either
 * is overwritten.  Pair with vm_orxor_pair64_loop completes the OR/AND
 * direction of the same shape.
 */
#include <stdio.h>
#include <stdint.h>

enum AxpVmPc {
    AXP_INIT_ALL = 0,
    AXP_CHECK    = 1,
    AXP_BODY     = 2,
    AXP_INC      = 3,
    AXP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_andxor_pair64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t i  = 0;
    int      pc = AXP_INIT_ALL;

    while (1) {
        if (pc == AXP_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = 0xFFFFFFFFFFFFFFFFull;
            b = x;
            i = 0ull;
            pc = AXP_CHECK;
        } else if (pc == AXP_CHECK) {
            pc = (i < n) ? AXP_BODY : AXP_HALT;
        } else if (pc == AXP_BODY) {
            uint64_t t = a;
            a = a & b;
            b = t ^ (b * 7ull);
            pc = AXP_INC;
        } else if (pc == AXP_INC) {
            i = i + 1ull;
            pc = AXP_CHECK;
        } else if (pc == AXP_HALT) {
            return a + b;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_andxor_pair64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_andxor_pair64_loop_target(0xCAFEBABEull));
    return 0;
}
