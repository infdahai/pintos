#pragma once

#include <stdint.h>
typedef int fix_point;

static int f = 16384; // 1<<14

static inline fix_point
itof (int n)
{
  return n * f;
}

static inline int
ftoi (fix_point x)
{
  return x / f;
}

static inline int
ftoi_near (fix_point x)
{
  return x >= 0 ? (x + f / 2) / f : (x - f / 2) / f;
}

static inline fix_point
fix_add (fix_point x, int n)
{
  return x + n * f;
}

static inline fix_point
fix_sub (fix_point x, int n)
{
  return x - n * f;
}

static inline fix_point
fix_mul (fix_point x, fix_point y)
{
  return ((int64_t)x) * y / f;
}

static inline fix_point
fix_div (fix_point x, fix_point y)
{
  return ((int64_t)x) * f / y;
}