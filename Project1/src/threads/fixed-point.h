#ifndef THREAD_FIXED_POINT_H
#define THREAD_FIXED_POINT_H
#include "lib/stdint.h"
#define FRACTION (1 << 14)

typedef int32_t fixed_point;

fixed_point int_to_fp (int n);

int fp_to_int_zero (fixed_point x);

int fp_to_int_nearest (fixed_point x);

fixed_point add_fps (fixed_point x, fixed_point y);

fixed_point add_fp_int (fixed_point x, int n);

fixed_point sub_fps (fixed_point x, fixed_point y);

fixed_point sub_fp_int (fixed_point x, int n);

fixed_point mul_fps (fixed_point x, fixed_point y);

fixed_point mul_fp_int (fixed_point x, int n);

fixed_point div_fps (fixed_point x, fixed_point y);

fixed_point div_fp_int (fixed_point x, int n);


#endif 
