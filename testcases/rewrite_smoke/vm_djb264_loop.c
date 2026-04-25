/* PC-state VM running an i64 djb2-style hash over the bytes of x.
 *   h = 5381;
 *   for i in 0..n: { b = (x >> (i*8)) & 0xFF; h = h * 33 + b; }
 *   return h;
 * Where n = (x & 7) + 1 (1..8 bytes consumed).  Returns full uint64_t.
 * Lift target: vm_djb264_loop_target.
 *
 * Distinct from vm_djb2_loop (i32 hash): exercises i64 mul-by-33 + i64
 * add inside a variable-trip loop body that also performs a symbolic
 * shift-by-loop-counter byte extraction.
 */
#include <stdio.h>
#include <stdint.h>

enum DjVmPc {
    DJ_LOAD       = 0,
    DJ_INIT       = 1,
    DJ_LOOP_CHECK = 2,
    DJ_LOOP_BODY  = 3,
    DJ_LOOP_INC   = 4,
    DJ_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_djb264_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t h   = 0;
    uint64_t xx  = 0;
    int      pc  = DJ_LOAD;

    while (1) {
        if (pc == DJ_LOAD) {
            n  = (int)(x & 7ull) + 1;
            xx = x;
            h  = 5381ull;
            pc = DJ_INIT;
        } else if (pc == DJ_INIT) {
            idx = 0;
            pc = DJ_LOOP_CHECK;
        } else if (pc == DJ_LOOP_CHECK) {
            pc = (idx < n) ? DJ_LOOP_BODY : DJ_HALT;
        } else if (pc == DJ_LOOP_BODY) {
            uint64_t b = (xx >> (idx * 8)) & 0xFFull;
            h = h * 33ull + b;
            pc = DJ_LOOP_INC;
        } else if (pc == DJ_LOOP_INC) {
            idx = idx + 1;
            pc = DJ_LOOP_CHECK;
        } else if (pc == DJ_HALT) {
            return h;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_djb264(0xCAFEBABE)=%llu vm_djb264(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_djb264_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_djb264_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
