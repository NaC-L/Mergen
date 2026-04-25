/* PC-state VM that sums sext-i32 dwords per iteration:
 *
 *   n = (x & 1) + 1;     // 1..2 dword iters
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     r = r + (int64_t)sd;     // sext i32 -> i64
 *     s >>= 32;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_signed_dword_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_signedbytesum64_loop  (sext-i8 byte sum, 8-bit stride)
 *   - vm_dword_xormul64_loop   (zext-i32 dword XOR, no sign extension)
 *
 * Tests `sext i32 to i64` per iteration on a 32-bit dword stream
 * (high bit of dword sign-extends).  Negative-dword inputs land
 * near 2^64 - magnitude in the sum.
 */
#include <stdio.h>
#include <stdint.h>

enum SdVmPc {
    SD_INIT_ALL = 0,
    SD_CHECK    = 1,
    SD_BODY     = 2,
    SD_INC      = 3,
    SD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_signed_dword_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    uint64_t i  = 0;
    int      pc = SD_INIT_ALL;

    while (1) {
        if (pc == SD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0;
            i = 0ull;
            pc = SD_CHECK;
        } else if (pc == SD_CHECK) {
            pc = (i < n) ? SD_BODY : SD_HALT;
        } else if (pc == SD_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            r = r + (int64_t)sd;
            s = s >> 32;
            pc = SD_INC;
        } else if (pc == SD_INC) {
            i = i + 1ull;
            pc = SD_CHECK;
        } else if (pc == SD_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_dword_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_signed_dword_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
