/* PC-state VM running a TEA-style (Tiny Encryption Algorithm) round loop.
 *   Three independently loop-carried state variables: v0, v1, sum.
 *   Each iteration:
 *     sum += delta;
 *     v0  += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
 *     v1  += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
 *   This compound cross-update is the canonical multi-slot loop-carried
 *   state pattern that requires the lifter to generalize ALL three varying
 *   memory slots, not just two (control + target).
 *
 * Trip count: n = (x & 0x1F) + 1  (1..32 rounds).
 * Keys are derived from x to keep the sample self-contained.
 * Returns v0 ^ v1 as a 64-bit summary.
 * Lift target: vm_tea_round_loop_target.
 */
#include <stdio.h>
#include <stdint.h>

enum TeaVmPc {
    TEA_LOAD       = 0,
    TEA_INIT       = 1,
    TEA_LOOP_CHECK = 2,
    TEA_LOOP_BODY  = 3,
    TEA_LOOP_INC   = 4,
    TEA_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_tea_round_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t v0    = 0;
    uint64_t v1    = 0;
    uint64_t sum   = 0;
    uint64_t delta = 0x9E3779B97F4A7C15ull;
    uint64_t k0    = 0;
    uint64_t k1    = 0;
    uint64_t k2    = 0;
    uint64_t k3    = 0;
    int      pc    = TEA_LOAD;

    while (1) {
        if (pc == TEA_LOAD) {
            n   = (int)(x & 0x1Full) + 1;
            v0  = x;
            v1  = x ^ 0xDEADBEEFCAFEBABEull;
            k0  = (x >> 8)  ^ 0xA1B2C3D4E5F60718ull;
            k1  = (x >> 16) ^ 0x1122334455667788ull;
            k2  = (x >> 24) ^ 0x99AABBCCDDEEFF00ull;
            k3  = (x >> 32) ^ 0xFEDCBA9876543210ull;
            pc  = TEA_INIT;
        } else if (pc == TEA_INIT) {
            idx = 0;
            sum = 0;
            pc  = TEA_LOOP_CHECK;
        } else if (pc == TEA_LOOP_CHECK) {
            pc = (idx < n) ? TEA_LOOP_BODY : TEA_HALT;
        } else if (pc == TEA_LOOP_BODY) {
            sum += delta;
            v0  += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
            v1  += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
            pc   = TEA_LOOP_INC;
        } else if (pc == TEA_LOOP_INC) {
            idx = idx + 1;
            pc  = TEA_LOOP_CHECK;
        } else if (pc == TEA_HALT) {
            return v0 ^ v1;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("tea(0x65501)=0x%llx tea(1)=0x%llx\n",
           (unsigned long long)vm_tea_round_loop_target(0x65501ull),
           (unsigned long long)vm_tea_round_loop_target(1ull));
    return 0;
}
