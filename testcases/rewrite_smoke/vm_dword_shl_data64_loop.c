/* PC-state VM with DATA-DEPENDENT shift amount inside the loop body
 * at u32 dword stride:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     r = (r << (d & 31)) | (d >> 16);   // shl amount comes from dword data
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_shl_data64_loop_target.
 *
 * Distinct from:
 *   - vm_word_shl_data64_loop  (16-bit stride, 4-bit shift mask)
 *   - vm_byteshl_data64_loop   (8-bit stride, 3-bit shift mask)
 *   - vm_dynshl_accum_dword64_loop (counter-derived shift amount)
 *
 * Tests `shl i64 r, %dword_amount` (data-derived 5-bit shift amount)
 * combined with OR of dword's high half at u32 stride.  Trip count
 * <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DshdVmPc {
    DSHD2_INIT_ALL = 0,
    DSHD2_CHECK    = 1,
    DSHD2_BODY     = 2,
    DSHD2_INC      = 3,
    DSHD2_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dword_shl_data64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DSHD2_INIT_ALL;

    while (1) {
        if (pc == DSHD2_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DSHD2_CHECK;
        } else if (pc == DSHD2_CHECK) {
            pc = (i < n) ? DSHD2_BODY : DSHD2_HALT;
        } else if (pc == DSHD2_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            r = (r << (d & 31ull)) | (d >> 16);
            s = s >> 32;
            pc = DSHD2_INC;
        } else if (pc == DSHD2_INC) {
            i = i + 1ull;
            pc = DSHD2_CHECK;
        } else if (pc == DSHD2_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_shl_data64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_dword_shl_data64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
