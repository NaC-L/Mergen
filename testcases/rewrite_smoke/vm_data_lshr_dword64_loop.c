/* PC-state VM with DATA-DEPENDENT right-shift amount inside the loop
 * at u32 dword stride:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = ~0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     r = (r >> (d & 31)) ^ d;   // lshr amount comes from dword data low 5 bits
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_data_lshr_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_data_lshr_word64_loop (16-bit lane stride, 4-bit shift amount mask)
 *   - vm_data_lshr64_loop      (byte stride, 3-bit shift amount mask)
 *
 * Tests `lshr i64 r, %dword_amount` (right-shift by dword-derived 5-bit
 * amount) at u32 stride.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DldVmPc {
    DLD2_INIT_ALL = 0,
    DLD2_CHECK    = 1,
    DLD2_BODY     = 2,
    DLD2_INC      = 3,
    DLD2_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_data_lshr_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DLD2_INIT_ALL;

    while (1) {
        if (pc == DLD2_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0xFFFFFFFFFFFFFFFFull;
            i = 0ull;
            pc = DLD2_CHECK;
        } else if (pc == DLD2_CHECK) {
            pc = (i < n) ? DLD2_BODY : DLD2_HALT;
        } else if (pc == DLD2_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            r = (r >> (d & 31ull)) ^ d;
            s = s >> 32;
            pc = DLD2_INC;
        } else if (pc == DLD2_INC) {
            i = i + 1ull;
            pc = DLD2_CHECK;
        } else if (pc == DLD2_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_data_lshr_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_data_lshr_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
