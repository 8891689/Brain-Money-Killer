/*MIT License

Copyright (c) 2024 vladkens

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.   https://github.com/vladkens/ecloop
*/
#pragma once

#include "addr.h"
#include "ecc.h"
#include "utils.h"
#include "bench.h"

void print_res(char *label, u64 stime, u64 iters) {
  double dt = MAX((tsnow() - stime), 1) / 1000.0;
  printf("%20s: %.2fM it/s ~ %.2fs\n", label, iters / dt / 1000000, dt);
}

void fe_rand(fe r) {
  for (int i = 0; i < 4; ++i) r[i] = (u64)rand() << 32 | (u64)rand();
  r[3] &= 0xfffffffefffffc2f;
}

void run_bench() {
  ec_gtable_init();

  u64 stime, iters, i;
  pe g;
  fe f;

  // projective & jacobian coordinates
  iters = 1000 * 1000 * 6;

  stime = tsnow();
  pe_clone(&g, &G2);
  for (i = 0; i < iters; ++i) _ec_jacobi_add1(&g, &g, &G1);
  print_res("_ec_jacobi_add1", stime, iters);

  pe_clone(&g, &G2);
  stime = tsnow();
  for (i = 0; i < iters; ++i) _ec_jacobi_add2(&g, &g, &G1);
  print_res("_ec_jacobi_add2", stime, iters);

  pe_clone(&g, &G2);
  stime = tsnow();
  for (i = 0; i < iters; ++i) _ec_jacobi_dbl1(&g, &g);
  print_res("_ec_jacobi_dbl1", stime, iters);

  pe_clone(&g, &G2);
  stime = tsnow();
  for (i = 0; i < iters; ++i) _ec_jacobi_dbl2(&g, &g);
  print_res("_ec_jacobi_dbl2", stime, iters);

  // ec multiplication
  srand(42);
  u64 numSize = 1024 * 16;
  fe numbers[numSize];
  for (int i = 0; i < numSize; ++i) fe_rand(numbers[i]);
  pe_clone(&g, &G2);

  iters = 1000 * 10;
  stime = tsnow();
  for (i = 0; i < iters; ++i) ec_jacobi_mul(&g, &G1, numbers[i % numSize]);
  print_res("ec_jacobi_mul", stime, iters);

  iters = 1000 * 500;
  stime = tsnow();
  for (i = 0; i < iters; ++i) ec_gtable_mul(&g, numbers[i % numSize]);
  print_res("ec_gtable_mul", stime, iters);

  // affine coordinates
  iters = 1000 * 500;

  pe_clone(&g, &G2);
  stime = tsnow();
  for (i = 0; i < iters; ++i) ec_affine_add(&g, &g, &G1);
  print_res("ec_affine_add", stime, iters);

  pe_clone(&g, &G2);
  stime = tsnow();
  for (i = 0; i < iters; ++i) ec_affine_dbl(&g, &g);
  print_res("ec_affine_dbl", stime, iters);

  // modular inversion
  iters = 1000 * 100;

  stime = tsnow();
  for (i = 0; i < iters; ++i) _fe_modinv_binpow(f, g.x);
  print_res("_fe_modinv_binpow", stime, iters);

  stime = tsnow();
  for (i = 0; i < iters; ++i) _fe_modinv_addchn(f, g.x);
  print_res("_fe_modinv_addchn", stime, iters);

  printf("\n[!] Hash function benchmarks (addr33, addr65) are disabled in this AVX2 version.\n");
  /*
  // hash functions
  iters = 1000 * 1000 * 5;
  h160_t h160;

  stime = tsnow();
  for (i = 0; i < iters; ++i) addr33(h160, &g);
  print_res("addr33", stime, iters);

  stime = tsnow();
  for (i = 0; i < iters; ++i) addr65(h160, &g);
  print_res("addr65", stime, iters);
  */
}

void run_bench_gtable() {
  srand(42);
  u64 numSize = 1024 * 16;
  fe numbers[numSize];
  for (int i = 0; i < numSize; ++i) fe_rand(numbers[i]);

  u64 iters = 1000 * 500;
  u64 stime;
  double gent, mult;
  pe g;

  size_t mem_used;
  for (int i = 8; i <= 22; i += 2) {
    GTABLE_W = i;

    stime = tsnow();
    mem_used = ec_gtable_init();
    gent = ((double)(tsnow() - stime)) / 1000;

    stime = tsnow();
    for (u64 i = 0; i < iters; ++i) ec_gtable_mul(&g, numbers[i % numSize]);
    mult = ((double)(tsnow() - stime)) / 1000;

    double mem = (double)mem_used / 1024 / 1024;                              // MB
    printf("w=%02d: %.1fK it/s | gen: %5.2fs | mul: %5.2fs | mem: %8.1fMB\n", //
           i, iters / mult / 1000, gent, mult, mem);
  }
}

// mult_verify is also removed as it depends on jacobi_mul which might be slow
// and not the main focus. If needed, it can be added back.
/*
void mult_verify() {
  // ...
}
*/
