/* PC-state VM with DATA-DEPENDENT shift amount inside the loop body:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = (r << (b & 7)) | (b >> 4);   // shl amount comes from byte data
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byteshl_data64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_pack64_loop      (shl by loop index i)
 *   - vm_byteshl3_xor64_loop     (shl by i*3 - counter expression)
 *   - vm_bitfetch_window64_loop  (lshr by counter)
 *
 * Tests `shl i64 r, %byte_amount` where the shift amount is derived
 * from the BYTE STREAM rather than the loop counter.  Each iter's
 * amount is bounded to 0..7 by `& 7` so undefined-shift behavior is
 * avoided.  Combined with OR of the byte's high nibble.
 */
#include <stdio.h>
#include <stdint.h>

enum BdVmPc {
    BD_INIT_ALL = 0,
    BD_CHECK    = 1,
    BD_BODY     = 2,
    BD_INC      = 3,
    BD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_byteshl_data64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BD_INIT_ALL;

    while (1) {
        if (pc == BD_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BD_CHECK;
        } else if (pc == BD_CHECK) {
            pc = (i < n) ? BD_BODY : BD_HALT;
        } else if (pc == BD_BODY) {
            uint64_t b = s & 0xFFull;
            r = (r << (b & 7ull)) | (b >> 4);
            s = s >> 8;
            pc = BD_INC;
        } else if (pc == BD_INC) {
            i = i + 1ull;
            pc = BD_CHECK;
        } else if (pc == BD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byteshl_data64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_byteshl_data64_loop_target(0xDEADBEEFull));
    return 0;
}
