/* Sum a small constant stack-allocated array.
 * Lift target: calc_sum_array — concrete loop + stack array access.
 * 10 + 20 + 30 + 40 + 50 = 150.
 * Tests compiler-generated array init + indexed load in a loop. */
#include <stdio.h>

__declspec(noinline)
int calc_sum_array(void) {
    int arr[] = {10, 20, 30, 40, 50};
    int sum = 0;
    for (int i = 0; i < 5; i++)
        sum += arr[i];
    return sum;
}

int main(void) {
    printf("sum([10,20,30,40,50])=%d\n", calc_sum_array());
    return 0;
}
