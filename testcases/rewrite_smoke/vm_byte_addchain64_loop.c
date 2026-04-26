/* PC-state VM that ADD-folds u8 bytes over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r + (s & 0xFF);
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_byte_addchain64_loop_target.
 *
 * Distinct from:
 *   - vm_word_addchain64_loop  (16-bit word stride)
 *   - vm_byte_orfold64_loop    (OR fold)
 *   - vm_byte_andfold64_loop   (AND fold)
 *   - vm_signedbytesum64_loop  (sext-i8 add)
 *
 * Tests `add i64` chain at 8-bit byte stride with zext-i8.  All-FF
 * input accumulates 8 * 0xFF = 2040.
 */
#include <stdio.h>
#include <stdint.h>

enum BcVmPc {
    BC_INIT_ALL = 0,
    BC_CHECK    = 1,
    BC_BODY     = 2,
    BC_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_addchain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = BC_INIT_ALL;

    while (1) {
        if (pc == BC_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            pc = BC_CHECK;
        } else if (pc == BC_CHECK) {
            pc = (n > 0ull) ? BC_BODY : BC_HALT;
        } else if (pc == BC_BODY) {
            r = r + (s & 0xFFull);
            s = s >> 8;
            n = n - 1ull;
            pc = BC_CHECK;
        } else if (pc == BC_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_addchain64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_addchain64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
