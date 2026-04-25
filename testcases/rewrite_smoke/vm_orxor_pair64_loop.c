/* PC-state VM that runs a two-state OR/XOR-mul cross-feed:
 *
 *   n = (x & 7) + 1;
 *   a = x; b = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t t = a;
 *     a = a | b;
 *     b = t ^ (b * 7);
 *   }
 *   return a + b;
 *
 * Lift target: vm_orxor_pair64_loop_target.
 *
 * Distinct from:
 *   - vm_pairmix64_loop          (two-state with add+mul-by-GR cross-feed)
 *   - vm_threestate_xormul64_loop (three-state cross-feed with mul-by-GR)
 *   - vm_orsum_byte_idx64_loop   (single-state OR fold over bytes)
 *
 * Tests an explicit temp barrier (`t = a`) so the OR (`a |= b`) and
 * XOR-mul (`b = t ^ b*7`) updates both see the original a value
 * before either is overwritten.  Combines monotone OR fold on `a`
 * with non-monotone XOR-mul evolution on `b`, returning a+b.
 */
#include <stdio.h>
#include <stdint.h>

enum OxVmPc {
    OX_INIT_ALL = 0,
    OX_CHECK    = 1,
    OX_BODY     = 2,
    OX_INC      = 3,
    OX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_orxor_pair64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t i  = 0;
    int      pc = OX_INIT_ALL;

    while (1) {
        if (pc == OX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = x;
            b = 0ull;
            i = 0ull;
            pc = OX_CHECK;
        } else if (pc == OX_CHECK) {
            pc = (i < n) ? OX_BODY : OX_HALT;
        } else if (pc == OX_BODY) {
            uint64_t t = a;
            a = a | b;
            b = t ^ (b * 7ull);
            pc = OX_INC;
        } else if (pc == OX_INC) {
            i = i + 1ull;
            pc = OX_CHECK;
        } else if (pc == OX_HALT) {
            return a + b;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_orxor_pair64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_orxor_pair64_loop_target(0xCAFEBABEull));
    return 0;
}
