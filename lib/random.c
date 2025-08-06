/* random.c 
* https://github.com/8891689 
*/
#include "random.h"

/* PCG 常量：使用 64 位 LCG，乘数为 6364136223846793005，
*  增量必须为奇数，这里任选一个常用值。
*/
#define PCG_MULT 6364136223846793005ULL
#define PCG_INC  1442695040888963407ULL

/* 内部状态 */
static uint64_t pcg_state = 0;

/* 初始化种子 */
void rseed(uint64_t seed) {
    /* 将状态设为 0，然后调用一次 rndu32() 来“混种” */
    pcg_state = 0;
    pcg_state += seed + PCG_INC;
    (void)rndu32();
}

/* 生成一个 32 位随机数（XSL RR 输出变换） */
uint32_t rndu32(void) {
    uint64_t oldstate = pcg_state;
    /* LCG 更新 */
    pcg_state = oldstate * PCG_MULT + PCG_INC;
    /* XSL RR 混淆 */
    uint32_t xorshifted = (uint32_t)(((oldstate >> 18u) ^ oldstate) >> 27u);
    uint32_t rot = (uint32_t)(oldstate >> 59u);
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

/* 生成 (0,1) 区间的 double，取 53 位精度 */
double rnd(void) {
    /* 生成 53 位随机整数，然后除以 2^53 */
    uint64_t hi = rndu32() & 0x1FFFFFUL;        // 高 21 位
    uint64_t lo = rndu32();                     // 低 32 位
    uint64_t mant = (hi << 32) | lo;            // 共 53 位
    return (mant + 1) / 9007199254740992.0;     // 2^53 = 9007199254740992
}

