/* bitrange.c
* https://github.com/8891689 
* gcc -std=c11 -O2 bitrange.c main.c -lgmp -o test_range
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitrange.h"

#define MAX_BITS 256
#define MIN_BITS   1

int set_bitrange(const char *param, mpz_t min_out, mpz_t max_out) {
    char *endptr = NULL;
    long bits = strtol(param, &endptr, 10);
    if (endptr == param || *endptr != '\0'
     || bits < MIN_BITS || bits > MAX_BITS) {
        fprintf(stderr, "[E] -b 参数必须为 %d~%d 之间的整数: '%s'\n",
                MIN_BITS, MAX_BITS, param);
        return -1;
    }
    /* min = 2^(bits-1) */
    mpz_ui_pow_ui(min_out, 2, (unsigned long)(bits - 1));
    /* max = 2^bits - 1 */
    mpz_ui_pow_ui(max_out, 2, (unsigned long)bits);
    mpz_sub_ui(max_out, max_out, 1UL);

    //gmp_fprintf(stderr,
       // "[+] bits=%ld → min=2^(%ld-1)=%Zx, max=2^%ld-1=%Zx\n",
       // bits, bits, min_out, bits, max_out);
    return 0;
}

int set_range(const char *param, mpz_t min_out, mpz_t max_out) {
    /* 在 param 中查找唯一一个 ':' */
    const char *sep = strchr(param, ':');
    if (!sep || sep == param || *(sep+1) == '\0' || strchr(sep+1, ':')) {
        fprintf(stderr, "[E] -r 参数格式应为 A:B（十六进制），当前: '%s'\n",
                param);
        return -1;
    }
    size_t lenA = sep - param;
    size_t lenB = strlen(param) - lenA - 1;

    char *strA = malloc(lenA+1);
    char *strB = malloc(lenB+1);
    if (!strA || !strB) {
        fprintf(stderr, "[E] 内存分配失败\n");
        free(strA); free(strB);
        return -1;
    }
    memcpy(strA, param, lenA); strA[lenA] = '\0';
    memcpy(strB, sep+1, lenB); strB[lenB] = '\0';

    if (mpz_set_str(min_out, strA, 16) != 0
     || mpz_set_str(max_out, strB, 16) != 0) {
        fprintf(stderr, "[E] 十六进制解析失败: '%s' 或 '%s'\n",
                strA, strB);
        free(strA); free(strB);
        return -1;
    }

    //gmp_fprintf(stderr,
       // "[+] range=%s:%s → min=%Zx, max=%Zx\n",
        //param, param, min_out, max_out);

    free(strA);
    free(strB);
    return 0;
}

