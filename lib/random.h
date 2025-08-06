/* Apache License, Version 2.0
   Copyright [2025] [8891689]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   Author: 8891689 (https://github.com/8891689)
*/
/* random.h — PCG 随机数生成器接口
 * https://github.com/8891689
 */
#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

/* 用指定种子初始化 RNG */
void rseed(uint64_t seed);

/* 返回一个 32 位无符号随机数 */
uint32_t rndu32(void);

/* 返回一个 (0,1) 区间的 double 随机数 */
double rnd(void);

#endif /* RANDOM_H */

