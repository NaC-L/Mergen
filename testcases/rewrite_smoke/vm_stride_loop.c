/* PC-state VM that sums every other element of a symbolic-content stack
 * array (stride-2 induction).
 * Lift target: vm_stride_loop_target.
 * Goal: cover a counted loop where the induction variable increments by 2
 * per iteration (BODY_INC: idx += 2).  Distinct from vm_skiploop_loop
 * (which still increments by 1 and skips body via parity branch) because
 * here the induction step itself is 2.
 */
#include <stdio.h>

enum SdVmPc {
    SD_LOAD       = 0,
    SD_INIT_FILL  = 1,
    SD_FILL_CHECK = 2,
    SD_FILL_BODY  = 3,
    SD_FILL_INC   = 4,
    SD_INIT_SUM   = 5,
    SD_SUM_CHECK  = 6,
    SD_SUM_BODY   = 7,
    SD_SUM_INC    = 8,
    SD_HALT       = 9,
};

__declspec(noinline)
int vm_stride_loop_target(int x) {
    int data[8];
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int pc    = SD_LOAD;

    while (1) {
        if (pc == SD_LOAD) {
            limit = (x & 7) + 1;
            sum = 0;
            pc = SD_INIT_FILL;
        } else if (pc == SD_INIT_FILL) {
            idx = 0;
            pc = SD_FILL_CHECK;
        } else if (pc == SD_FILL_CHECK) {
            pc = (idx < limit) ? SD_FILL_BODY : SD_INIT_SUM;
        } else if (pc == SD_FILL_BODY) {
            data[idx] = (x ^ (idx * 0x5A)) & 0xFF;
            pc = SD_FILL_INC;
        } else if (pc == SD_FILL_INC) {
            idx = idx + 1;
            pc = SD_FILL_CHECK;
        } else if (pc == SD_INIT_SUM) {
            idx = 0;
            pc = SD_SUM_CHECK;
        } else if (pc == SD_SUM_CHECK) {
            pc = (idx < limit) ? SD_SUM_BODY : SD_HALT;
        } else if (pc == SD_SUM_BODY) {
            sum = sum + data[idx];
            pc = SD_SUM_INC;
        } else if (pc == SD_SUM_INC) {
            idx = idx + 2;
            pc = SD_SUM_CHECK;
        } else if (pc == SD_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_stride_loop(0xFF)=%d vm_stride_loop(0xABCDEF)=%d\n",
           vm_stride_loop_target(0xFF), vm_stride_loop_target(0xABCDEF));
    return 0;
}
