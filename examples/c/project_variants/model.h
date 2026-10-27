#ifndef HEPTA_C_MATRIX_MODEL_H
#define HEPTA_C_MATRIX_MODEL_H
#if PROJECT_VARIANT == 1
#define PROJECT_ROUNDS 2
#define PROJECT_BIAS 3u
#elif PROJECT_VARIANT == 2
#define PROJECT_ROUNDS 4
#define PROJECT_BIAS 17u
#else
#error An explicit supported PROJECT_VARIANT is required
#endif
unsigned int matrix_word(unsigned int value, unsigned int salt);
unsigned long long matrix_wide(unsigned long long value, unsigned long long salt);
unsigned long long matrix_cross(unsigned int value, unsigned long long salt);
#endif
