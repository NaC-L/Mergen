/* PC-state VM that counts SIGNED divisions of state by a small divisor
 * until state becomes non-positive.
 *   divisor = (x & 7) + 2;     // 2..9
 *   val     = (int64_t)x;
 *   count   = 0;
 *   while (val > 0) { val = val / divisor; count++; }
 *   return count;
 * Lift target: vm_sdiv64_loop_target.
 *
 * Distinct from vm_divcount64_loop (unsigned udiv with `state >= divisor`):
 * exercises i64 sdiv + signed comparison `val > 0` (icmp sgt) inside a
 * data-dependent loop.  Negative inputs (e.g. max u64 reads as -1) take
 * 0 trips because the signed comparison fails immediately.
 */
#include <stdio.h>
#include <stdint.h>

enum SdVmPc {
    SD_LOAD       = 0,
    SD_LOOP_CHECK = 1,
    SD_LOOP_BODY  = 2,
    SD_HALT       = 3,
};

__declspec(noinline)
int vm_sdiv64_loop_target(int64_t x) {
    int64_t divisor = 0;
    int64_t val     = 0;
    int     count   = 0;
    int     pc      = SD_LOAD;

    while (1) {
        if (pc == SD_LOAD) {
            divisor = (int64_t)((uint64_t)x & 7ull) + 2;
            val     = x;
            count   = 0;
            pc = SD_LOOP_CHECK;
        } else if (pc == SD_LOOP_CHECK) {
            pc = (val > 0) ? SD_LOOP_BODY : SD_HALT;
        } else if (pc == SD_LOOP_BODY) {
            val = val / divisor;
            count = count + 1;
            pc = SD_LOOP_CHECK;
        } else if (pc == SD_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_sdiv64(1000)=%d vm_sdiv64(0x7FFFFFFFFFFFFFFF)=%d\n",
           vm_sdiv64_loop_target((int64_t)1000),
           vm_sdiv64_loop_target((int64_t)0x7FFFFFFFFFFFFFFFll));
    return 0;
}
