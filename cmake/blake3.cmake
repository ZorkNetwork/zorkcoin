# Copyright (c) 2026 ADGL Enterprises, LLC
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Builds the BLAKE3 subtree with SIMD implementations selected by compiler
# introspection. blake3_dispatch.c picks among the compiled-in x86
# implementations at runtime via cpuid; on little-endian AArch64, NEON is
# architecturally guaranteed when compiled in. All other targets (including
# RISC-V) keep only blake3_portable.c — blake3_impl.h sets BLAKE3_USE_NEON=0
# and MAX_SIMD_DEGREE=1 when neither IS_X86 nor NEON applies. Every
# implementation that is not compiled must be disabled with BLAKE3_NO_* or
# BLAKE3_USE_NEON=0, consistently across all BLAKE3 sources.

enable_language(C)
include(CheckCXXSourceCompiles)
include(CheckSourceCompilesWithFlags)

# HAVE_SSE41/SSE41_CXXFLAGS and HAVE_AVX2/AVX2_CXXFLAGS are provided by
# introspection.cmake. As there, MSVC is left on the portable implementation.
if(NOT MSVC)
  set(SSE2_CXXFLAGS -msse2)
  check_cxx_source_compiles_with_flags("
    #include <immintrin.h>

    int main()
    {
      __m128i a = _mm_set1_epi32(1);
      return _mm_cvtsi128_si32(_mm_add_epi32(a, a));
    }
    " HAVE_SSE2
    CXXFLAGS ${SSE2_CXXFLAGS}
  )

  set(AVX512_CXXFLAGS -mavx512f -mavx512vl)
  check_cxx_source_compiles_with_flags("
    #include <immintrin.h>

    int main()
    {
      __m256i a = _mm256_set1_epi32(1);
      return _mm256_extract_epi32(_mm256_ror_epi32(a, 7), 0);
    }
    " HAVE_AVX512
    CXXFLAGS ${AVX512_CXXFLAGS}
  )

  # Only probe NEON when the CMake *target* is AArch64/arm64. Do not rely on
  # try_compile alone: a host AArch64 toolchain can otherwise make the probe
  # succeed while cross-compiling for RISC-V or other ISAs without NEON.
  set(HAVE_BLAKE3_NEON FALSE)
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _blake3_system_processor)
  if(_blake3_system_processor MATCHES "^(aarch64|arm64)")
    check_cxx_source_compiles("
      #if !defined(__aarch64__) || defined(__ARM_BIG_ENDIAN)
      #error BLAKE3 NEON requires little-endian AArch64
      #endif
      #include <arm_neon.h>

      int main()
      {
        uint32x4_t a = vdupq_n_u32(1);
        return vgetq_lane_u32(vaddq_u32(a, a), 0);
      }
      " HAVE_BLAKE3_NEON
    )
  endif()
  unset(_blake3_system_processor)
endif()

set(_blake3_dir ${PROJECT_SOURCE_DIR}/src/crypto/blake3)

add_library(blake3 STATIC EXCLUDE_FROM_ALL
  ${_blake3_dir}/blake3.c
  ${_blake3_dir}/blake3_dispatch.c
  ${_blake3_dir}/blake3_portable.c
)
target_link_libraries(blake3 PRIVATE sanitize_interface)
set_target_properties(blake3 PROPERTIES
  C_VISIBILITY_PRESET hidden
  EXPORT_COMPILE_COMMANDS OFF
)

if(HAVE_SSE2)
  target_sources(blake3 PRIVATE ${_blake3_dir}/blake3_sse2.c)
  set_property(SOURCE ${_blake3_dir}/blake3_sse2.c PROPERTY COMPILE_OPTIONS ${SSE2_CXXFLAGS})
else()
  target_compile_definitions(blake3 PRIVATE BLAKE3_NO_SSE2)
endif()

if(HAVE_SSE41)
  target_sources(blake3 PRIVATE ${_blake3_dir}/blake3_sse41.c)
  set_property(SOURCE ${_blake3_dir}/blake3_sse41.c PROPERTY COMPILE_OPTIONS ${SSE41_CXXFLAGS})
else()
  target_compile_definitions(blake3 PRIVATE BLAKE3_NO_SSE41)
endif()

if(HAVE_AVX2)
  target_sources(blake3 PRIVATE ${_blake3_dir}/blake3_avx2.c)
  set_property(SOURCE ${_blake3_dir}/blake3_avx2.c PROPERTY COMPILE_OPTIONS ${AVX2_CXXFLAGS})
else()
  target_compile_definitions(blake3 PRIVATE BLAKE3_NO_AVX2)
endif()

if(HAVE_AVX512)
  target_sources(blake3 PRIVATE ${_blake3_dir}/blake3_avx512.c)
  set_property(SOURCE ${_blake3_dir}/blake3_avx512.c PROPERTY COMPILE_OPTIONS ${AVX512_CXXFLAGS})
else()
  target_compile_definitions(blake3 PRIVATE BLAKE3_NO_AVX512)
endif()

if(HAVE_BLAKE3_NEON)
  target_sources(blake3 PRIVATE ${_blake3_dir}/blake3_neon.c)
endif()
target_compile_definitions(blake3 PRIVATE BLAKE3_USE_NEON=$<BOOL:${HAVE_BLAKE3_NEON}>)

unset(_blake3_dir)
