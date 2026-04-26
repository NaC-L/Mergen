/* PC-state VM running a three-op single-state chain over n iterations
 * with the additive op replaced by SUB:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ x;
 *     r = r * 0x1000193ull;     // 24-bit FNV-32 prime
 *     r = r - x;                 // SUB instead of ADD
 *   }
 *   return r;
 *
 * Lift target: vm_xormulsub_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_xormuladd_chain64_loop (sister: ADD instead of SUB)
 *   - vm_subxor_chain64_loop    ((r-x) ^ (x<<3), no mul)
 *
 * Same xor + mul + last-op shape as vm_xormuladd_chain64_loop, but the
 * trailing add becomes a sub.  Result wraps below zero into u64
 * modular space.
 */
#include <stdio.h>
#include <stdint.h>

enum XmsVmPc {
    XMS_INIT_ALL = 0,
    XMS_CHECK    = 1,
    XMS_BODY     = 2,
    XMS_INC      = 3,
    XMS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormulsub_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XMS_INIT_ALL;

    while (1) {
        if (pc == XMS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = XMS_CHECK;
        } else if (pc == XMS_CHECK) {
            pc = (i < n) ? XMS_BODY : XMS_HALT;
        } else if (pc == XMS_BODY) {
            r = r ^ x;
            r = r * 0x1000193ull;
            r = r - x;
            pc = XMS_INC;
        } else if (pc == XMS_INC) {
            i = i + 1ull;
            pc = XMS_CHECK;
        } else if (pc == XMS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormulsub_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormulsub_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
