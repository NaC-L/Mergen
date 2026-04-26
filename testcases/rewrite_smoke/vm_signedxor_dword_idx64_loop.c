/* PC-state VM that XORs (sext-i32 dword * counter) into the accumulator
 * over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     r = r ^ (uint64_t)((int64_t)sd * (int64_t)(i + 1));
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_signedxor_dword_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_signedxor_word_idx64_loop (16-bit lane stride)
 *   - vm_signedxor_byte_idx64_loop (8-bit lane stride)
 *   - vm_xormul_dword_idx64_loop   (zext-i32 XOR counterpart)
 *
 * Tests sext-i32 dword * counter XOR-folded into i64 accumulator at
 * u32 stride.  Trip count <= 2.
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
uint64_t vm_signedxor_dword_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SD_INIT_ALL;

    while (1) {
        if (pc == SD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SD_CHECK;
        } else if (pc == SD_CHECK) {
            pc = (i < n) ? SD_BODY : SD_HALT;
        } else if (pc == SD_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            r = r ^ (uint64_t)((int64_t)sd * (int64_t)(i + 1ull));
            s = s >> 32;
            pc = SD_INC;
        } else if (pc == SD_INC) {
            i = i + 1ull;
            pc = SD_CHECK;
        } else if (pc == SD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signedxor_dword_idx64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_signedxor_dword_idx64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
