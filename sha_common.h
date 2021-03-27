#pragma once
#include <cstdint>

#if defined(_DEBUG) || !defined(NDEBUG)
#define SHA_CPP_DEBUG
#include <cassert>
#endif

#ifdef _MSVC_LANG
#include <intrin.h>
#include <cstring>
#define SHA_CPP_INLINE_ALWAYS __forceinline
#define SHA_CPP_INLINE_NEVER __declspec(noinline)
#define SHA_CPP_RESTRICT __restrict
#ifdef SHA_CPP_BIG_ENDIAN
#define SHA_CPP_BSWAP64(MASK) _byteswap_uint64((MASK))
#endif
#define SHA_CPP_ROTL64(MASK, AMOUNT) _rotl64((MASK), (AMOUNT))
#else // assume CLang-like compiler
#define SHA_CPP_INLINE_ALWAYS __attribute__((always_inline))
#define SHA_CPP_INLINE_NEVER __attribute__((noinline))
#define SHA_CPP_RESTRICT __restrict__
#ifdef SHA_CPP_BIG_ENDIAN
#define SHA_CPP_BSWAP64(MASK) __bswap64((MASK))
#endif
#define SHA_CPP_ROTL64(MASK, AMOUNT) __builtin_rotateleft64((MASK), (AMOUNT))
#endif

#ifdef SHA_CPP_STRING_VIEW
#include <string_view>
#endif

namespace sha_cpp
{
	namespace detail
	{
		constexpr char hex_lookup_upper[] =
			"000102030405060708090A0B0C0D0E0F"
			"101112131415161718191A1B1C1D1E1F"
			"202122232425262728292A2B2C2D2E2F"
			"303132333435363738393A3B3C3D3E3F"
			"404142434445464748494A4B4C4D4E4F"
			"505152535455565758595A5B5C5D5E5F"
			"606162636465666768696A6B6C6D6E6F"
			"707172737475767778797A7B7C7D7E7F"
			"808182838485868788898A8B8C8D8E8F"
			"909192939495969798999A9B9C9D9E9F"
			"A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
			"B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
			"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
			"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
			"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
			"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
		constexpr char hex_lookup_lower[] =
			"000102030405060708090a0b0c0d0e0f"
			"101112131415161718191a1b1c1d1e1f"
			"202122232425262728292a2b2c2d2e2f"
			"303132333435363738393a3b3c3d3e3f"
			"404142434445464748494a4b4c4d4e4f"
			"505152535455565758595a5b5c5d5e5f"
			"606162636465666768696a6b6c6d6e6f"
			"707172737475767778797a7b7c7d7e7f"
			"808182838485868788898a8b8c8d8e8f"
			"909192939495969798999a9b9c9d9e9f"
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
			"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
			"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
			"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
			"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
	}

	template <uint32_t Bits>
	struct hash
	{
		static constexpr uint32_t hash_bits = Bits;
		static constexpr uint32_t hash_bytes = hash_bits / 8;
		static constexpr uint32_t hash_qwords = hash_bytes / 8;

		static constexpr uint32_t hex_digit_count = hash_bytes * 2;

		uint64_t hash_data[hash_qwords];

		template <bool LowerCase = true>
		void to_hex(char* out)
		{
			// Johnny Lee's uint64_t to hex string:
			// https://johnnylee-sde.github.io/Fast-unsigned-integer-to-hex-string/

			constexpr auto& lookup = (LowerCase ? detail::hex_lookup_lower : detail::hex_lookup_upper);
			for (uint_fast8_t mask_index = 0; mask_index != hash_qwords; ++mask_index)
			{
				uint_fast64_t mask = hash_data[mask_index];
				uint_fast16_t lookup_index;

				lookup_index = (uint_fast16_t)2 * (uint8_t)mask;
				out[15] = lookup[lookup_index + 1];
				out[14] = lookup[lookup_index];
				mask >>= 8;

				lookup_index = (uint_fast16_t)2 * (uint8_t)mask;
				out[13] = lookup[lookup_index + 1];
				out[12] = lookup[lookup_index];
				mask >>= 8;

				lookup_index = (uint_fast16_t)2 * (uint8_t)mask;
				out[11] = lookup[lookup_index + 1];
				out[10] = lookup[lookup_index];
				mask >>= 8;

				lookup_index = (uint_fast16_t)2 * (uint8_t)mask;
				out[9] = lookup[lookup_index + 1];
				out[8] = lookup[lookup_index];
				mask >>= 8;

				lookup_index = (uint_fast16_t)2 * (uint8_t)mask;
				out[7] = lookup[lookup_index + 1];
				out[6] = lookup[lookup_index];
				mask >>= 8;

				lookup_index = (uint_fast16_t)2 * (uint8_t)mask;
				out[5] = lookup[lookup_index + 1];
				out[4] = lookup[lookup_index];
				mask >>= 8;

				lookup_index = (uint_fast16_t)2 * (uint8_t)mask;
				out[3] = lookup[lookup_index + 1];
				out[2] = lookup[lookup_index];
				mask >>= 8;

				lookup_index = (uint_fast16_t)2 * (uint8_t)mask;
				out[1] = lookup[lookup_index + 1];
				out[0] = lookup[lookup_index];
				mask >>= 8;

				out += 16;
			}
		}
	};

}