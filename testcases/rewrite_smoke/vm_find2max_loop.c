/* PC-state VM that finds the TWO largest values in a stack array, packing
 * them as top1 | (top2 << 8).
 * Lift target: vm_find2max_loop_target.
 * Goal: cover a loop body with a three-way update on two co-related state
 * vars (top1 and top2): if v > top1 the pair shifts (t2 := t1; t1 := v),
 * else-if v > t2 only t2 updates, else neither.  Distinct from
 * vm_argmax_loop (single max+idx) and vm_minarray_loop (single min only).
 */
#include <stdio.h>

enum FmVmPc {
    FM_LOAD       = 0,
    FM_INIT_FILL  = 1,
    FM_FILL_CHECK = 2,
    FM_FILL_BODY  = 3,
    FM_FILL_INC   = 4,
    FM_INIT_SCAN  = 5,
    FM_SCAN_CHECK = 6,
    FM_SCAN_LOAD  = 7,
    FM_SCAN_TEST1 = 8,
    FM_SCAN_TEST2 = 9,
    FM_UPD_TOP1   = 10,
    FM_UPD_TOP2   = 11,
    FM_SCAN_INC   = 12,
    FM_PACK       = 13,
    FM_HALT       = 14,
};

__declspec(noinline)
int vm_find2max_loop_target(int x) {
    int data[10];
    int limit  = 0;
    int idx    = 0;
    int top1   = 0;
    int top2   = 0;
    int v      = 0;
    int result = 0;
    int pc     = FM_LOAD;

    while (1) {
        if (pc == FM_LOAD) {
            limit = (x & 7) + 2;
            top1 = 0;
            top2 = 0;
            pc = FM_INIT_FILL;
        } else if (pc == FM_INIT_FILL) {
            idx = 0;
            pc = FM_FILL_CHECK;
        } else if (pc == FM_FILL_CHECK) {
            pc = (idx < limit) ? FM_FILL_BODY : FM_INIT_SCAN;
        } else if (pc == FM_FILL_BODY) {
            data[idx] = (x ^ (idx * 0x29)) & 0xFF;
            pc = FM_FILL_INC;
        } else if (pc == FM_FILL_INC) {
            idx = idx + 1;
            pc = FM_FILL_CHECK;
        } else if (pc == FM_INIT_SCAN) {
            idx = 0;
            pc = FM_SCAN_CHECK;
        } else if (pc == FM_SCAN_CHECK) {
            pc = (idx < limit) ? FM_SCAN_LOAD : FM_PACK;
        } else if (pc == FM_SCAN_LOAD) {
            v = data[idx];
            pc = FM_SCAN_TEST1;
        } else if (pc == FM_SCAN_TEST1) {
            pc = (v > top1) ? FM_UPD_TOP1 : FM_SCAN_TEST2;
        } else if (pc == FM_SCAN_TEST2) {
            pc = (v > top2) ? FM_UPD_TOP2 : FM_SCAN_INC;
        } else if (pc == FM_UPD_TOP1) {
            top2 = top1;
            top1 = v;
            pc = FM_SCAN_INC;
        } else if (pc == FM_UPD_TOP2) {
            top2 = v;
            pc = FM_SCAN_INC;
        } else if (pc == FM_SCAN_INC) {
            idx = idx + 1;
            pc = FM_SCAN_CHECK;
        } else if (pc == FM_PACK) {
            result = top1 + (top2 << 8);
            pc = FM_HALT;
        } else if (pc == FM_HALT) {
            return result;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_find2max_loop(0xFF)=%d vm_find2max_loop(0xABCDEF)=%d\n",
           vm_find2max_loop_target(0xFF), vm_find2max_loop_target(0xABCDEF));
    return 0;
}
