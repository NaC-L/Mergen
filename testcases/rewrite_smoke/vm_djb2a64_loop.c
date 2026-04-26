/* PC-state VM running an i64 djb2a-style (XOR variant) hash over the
 * bytes of x:
 *
 *   h = 5381;
 *   for i in 0..n: { b = (x >> (i*8)) & 0xFF; h = h * 33 ^ b; }
 *   return h;
 *
 * Where n = (x & 7) + 1 (1..8 bytes consumed).  Returns full uint64_t.
 *
 * Lift target: vm_djb2a64_loop_target.
 *
 * Distinct from:
 *   - vm_djb264_loop (sister: h = h*33 + b instead of h = h*33 ^ b)
 *
 * Same djb2 mul-by-33 hash chain over a symbolic shift-by-loop-counter
 * byte extraction, but combines via XOR instead of ADD.  Tests the
 * lifter's xor/add swap inside a hash loop with live-state recurrence.
 */
#include <stdio.h>
#include <stdint.h>

enum DjaVmPc {
    DJA_LOAD       = 0,
    DJA_INIT       = 1,
    DJA_LOOP_CHECK = 2,
    DJA_LOOP_BODY  = 3,
    DJA_LOOP_INC   = 4,
    DJA_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_djb2a64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t h   = 0;
    uint64_t xx  = 0;
    int      pc  = DJA_LOAD;

    while (1) {
        if (pc == DJA_LOAD) {
            n  = (int)(x & 7ull) + 1;
            xx = x;
            h  = 5381ull;
            pc = DJA_INIT;
        } else if (pc == DJA_INIT) {
            idx = 0;
            pc = DJA_LOOP_CHECK;
        } else if (pc == DJA_LOOP_CHECK) {
            pc = (idx < n) ? DJA_LOOP_BODY : DJA_HALT;
        } else if (pc == DJA_LOOP_BODY) {
            uint64_t b = (xx >> (idx * 8)) & 0xFFull;
            h = h * 33ull ^ b;
            pc = DJA_LOOP_INC;
        } else if (pc == DJA_LOOP_INC) {
            idx = idx + 1;
            pc = DJA_LOOP_CHECK;
        } else if (pc == DJA_HALT) {
            return h;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_djb2a64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_djb2a64_loop_target(0xCAFEBABEull));
    return 0;
}
