/* PC-state VM running an explicit PEXT-style parallel bit-extract.
 *   src = x;
 *   mask = 0xAAAAAAAAAAAAAAAA ^ (x >> 32);   // input-perturbed mask
 *   if (mask == 0) mask = 1;
 *   result = 0; bit_pos = 0;
 *   for i in 0..64:
 *     if ((mask >> i) & 1):
 *       if ((src >> i) & 1):
 *         result |= (1 << bit_pos);
 *       bit_pos++;
 *   return result;
 * Lift target: vm_pextslow64_loop_target.
 *
 * Distinct from vm_pdepslow64_loop (deposit/scatter): this is the
 * INVERSE - bits at mask-set positions in src are PACKED into low-order
 * bits of result.  The deposit position depends on a running counter
 * that advances asymmetrically.
 */
#include <stdio.h>
#include <stdint.h>

enum PxVmPc {
    PX_LOAD       = 0,
    PX_INIT       = 1,
    PX_LOOP_CHECK = 2,
    PX_LOOP_BODY  = 3,
    PX_LOOP_INC   = 4,
    PX_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_pextslow64_loop_target(uint64_t x) {
    int      idx     = 0;
    int      bit_pos = 0;
    uint64_t src     = 0;
    uint64_t mask    = 0;
    uint64_t result  = 0;
    int      pc      = PX_LOAD;

    while (1) {
        if (pc == PX_LOAD) {
            src    = x;
            mask   = 0xAAAAAAAAAAAAAAAAull ^ (x >> 32);
            if (mask == 0ull) {
                mask = 1ull;
            }
            result = 0ull;
            bit_pos = 0;
            pc = PX_INIT;
        } else if (pc == PX_INIT) {
            idx = 0;
            pc = PX_LOOP_CHECK;
        } else if (pc == PX_LOOP_CHECK) {
            pc = (idx < 64) ? PX_LOOP_BODY : PX_HALT;
        } else if (pc == PX_LOOP_BODY) {
            if (((mask >> idx) & 1ull) != 0ull) {
                if (((src >> idx) & 1ull) != 0ull) {
                    result = result | (1ull << bit_pos);
                }
                bit_pos = bit_pos + 1;
            }
            pc = PX_LOOP_INC;
        } else if (pc == PX_LOOP_INC) {
            idx = idx + 1;
            pc = PX_LOOP_CHECK;
        } else if (pc == PX_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pextslow64(0xCAFEBABE)=%llu vm_pextslow64(max)=%llu\n",
           (unsigned long long)vm_pextslow64_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_pextslow64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
