/* PC-state VM that counts hex digits (nibbles) of x via repeated >>4.
 *   if (x == 0) return 1;
 *   count = 0;
 *   while (state > 0) { state >>= 4; count++; }
 *   return count;
 * Variable trip 1..16.
 * Lift target: vm_hexdigits64_loop_target.
 *
 * Distinct from vm_decdigits64_loop (constant divisor 10 with udiv-by-10
 * magic-number fold) and vm_clz64_loop (single-bit shift): uses 4-bit
 * stride lshr with > 0 termination.  The optimizer may fold the loop to
 * llvm.ctlz-based digit-count; conservative patterns are lshr + icmp.
 */
#include <stdio.h>
#include <stdint.h>

enum HxVmPc {
    HX_LOAD       = 0,
    HX_ZERO_CHECK = 1,
    HX_LOOP_CHECK = 2,
    HX_LOOP_BODY  = 3,
    HX_HALT       = 4,
};

__declspec(noinline)
int vm_hexdigits64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = HX_LOAD;

    while (1) {
        if (pc == HX_LOAD) {
            state = x;
            count = 0;
            pc = HX_ZERO_CHECK;
        } else if (pc == HX_ZERO_CHECK) {
            if (state == 0ull) {
                count = 1;
                pc = HX_HALT;
            } else {
                pc = HX_LOOP_CHECK;
            }
        } else if (pc == HX_LOOP_CHECK) {
            pc = (state > 0ull) ? HX_LOOP_BODY : HX_HALT;
        } else if (pc == HX_LOOP_BODY) {
            state = state >> 4;
            count = count + 1;
            pc = HX_LOOP_CHECK;
        } else if (pc == HX_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_hexdigits64(0xCAFEBABE)=%d vm_hexdigits64(max)=%d\n",
           vm_hexdigits64_loop_target(0xCAFEBABEull),
           vm_hexdigits64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
