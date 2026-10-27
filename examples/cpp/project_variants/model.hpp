#ifndef HEPTA_MATRIX_MODEL_HPP
#define HEPTA_MATRIX_MODEL_HPP

#if PROJECT_VARIANT == 1
#define PROJECT_ROUNDS 2
#define PROJECT_BIAS 3u
#elif PROJECT_VARIANT == 2
#define PROJECT_ROUNDS 4
#define PROJECT_BIAS 17u
#else
#error An explicit supported PROJECT_VARIANT is required
#endif

template<class T, int Rounds>
T matrix_mix(T value, T salt) noexcept {
    for (int index = 0; index < Rounds; index = index + 1) {
        value = value * static_cast<T>(33) + salt + static_cast<T>(index);
    }
    return value + static_cast<T>(PROJECT_BIAS);
}

extern "C" unsigned int matrix_word(unsigned int value, unsigned int salt) noexcept;
extern "C" unsigned long long matrix_wide(unsigned long long value, unsigned long long salt) noexcept;
extern "C" unsigned long long matrix_cross(unsigned int value, unsigned long long salt) noexcept;

#endif
