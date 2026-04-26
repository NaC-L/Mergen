/* PC-state VM that packs the lower n = (x & 1) + 1 u32 dwords of x
 * into the accumulator r in REVERSED dword order:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << 32) | (s & 0xFFFFFFFF);
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dwordrev_window64_loop_target.
 *
 * Distinct from:
 *   - vm_wordrev_window64_loop (16-bit stride)
 *   - vm_byterev_window64_loop (8-bit stride)
 *
 * Tests shl-by-32 + or + lshr-by-32 chain inside a counter-bound loop
 * body at u32 stride.  Trip count <= 2.  When low bit set, n=2 swaps
 * the two dwords of x.
 */
#include <stdio.h>
#include <stdint.h>

enum DvVmPc {
    DV_INIT_ALL = 0,
    DV_CHECK    = 1,
    DV_PACK     = 2,
    DV_SHIFT    = 3,
    DV_INC      = 4,
    DV_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_dwordrev_window64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DV_INIT_ALL;

    while (1) {
        if (pc == DV_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DV_CHECK;
        } else if (pc == DV_CHECK) {
            pc = (i < n) ? DV_PACK : DV_HALT;
        } else if (pc == DV_PACK) {
            r = (r << 32) | (s & 0xFFFFFFFFull);
            pc = DV_SHIFT;
        } else if (pc == DV_SHIFT) {
            s = s >> 32;
            pc = DV_INC;
        } else if (pc == DV_INC) {
            i = i + 1ull;
            pc = DV_CHECK;
        } else if (pc == DV_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dwordrev_window64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_dwordrev_window64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
