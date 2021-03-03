#include "threads/fixed-point.h"
#include "lib/stdint.h"

fixed_point int_to_fp (int n) 
 {
	 return n * FRACTION;
 }

int fp_to_int_zero (fixed_point x)
	{
		return x / FRACTION;
	}

int fp_to_int_nearest (fixed_point x)
	{
		if (x >= 0)
			{
				return (x + FRACTION / 2) / FRACTION;
			}
		else
			{
				return (x - FRACTION / 2) / FRACTION;
			}
		
	}

fixed_point add_fps (fixed_point x, fixed_point y) 
	{
		return x + y;
	}

fixed_point add_fp_int (fixed_point x, int n) 
	{
		return x + n * FRACTION;
	}

fixed_point sub_fps (fixed_point x, fixed_point y)
	{
		return x - y;
	}

fixed_point sub_fp_int (fixed_point x, int n)
	{
		return x - n * FRACTION;
	}

fixed_point mul_fps (fixed_point x, fixed_point y)
	{
		return ((int64_t) x) * y / FRACTION;
	}

fixed_point mul_fp_int (fixed_point x, int n) 
	{
		return x * n;
	}

fixed_point div_fps (fixed_point x, fixed_point y)
	{
		return ((int64_t) x) * FRACTION / y;
	}

fixed_point div_fp_int (fixed_point x, int n)
	{
		return x / n;
	}
