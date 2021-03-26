/*
	BSD 2-Clause License
	
	Copyright (c) 2021, Marcel Pi Nacy
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
	
	1. Redistributions of source code must retain the above copyright notice, this
	   list of conditions and the following disclaimer.
	
	2. Redistributions in binary form must reproduce the above copyright notice,
	   this list of conditions and the following disclaimer in the documentation
	   and/or other materials provided with the distribution.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
	FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
	CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
	OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
#ifdef SHA_CPP_BIG_ENDIAN
#define SHA_CPP_BSWAP64(MASK) _byteswap_uint64((MASK))
#endif
#define SHA_CPP_ROTL64(MASK, AMOUNT) _rotl64((MASK), (AMOUNT))
#else // assume CLang-like compiler
#define SHA_CPP_INLINE_ALWAYS __attribute__((always_inline))
#define SHA_CPP_INLINE_NEVER __attribute__((noinline))
#ifdef SHA_CPP_BIG_ENDIAN
#define SHA_CPP_BSWAP64(MASK) __bswap64((MASK))
#endif
#define SHA_CPP_ROTL64(MASK, AMOUNT) __builtin_rotateleft64((MASK), (AMOUNT))
#endif

#ifdef SHA_CPP_STRING_VIEW
#include <string_view>
#endif

namespace sha3
{
	static constexpr uint8_t HASH_STATE_SIZE = 25;
	static constexpr uint8_t MAX_HASH_RATE = 24;

	template <typename T, uint32_t Size>
	using array_type = T[Size];

	template <typename T, uint32_t Size>
	using array_ref = array_type<T, Size>&;

	constexpr uint8_t KECCAK_ROUND_COUNT = 24;
	constexpr uint64_t KECCAK_ROUND_LOOKUP[KECCAK_ROUND_COUNT] =
	{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
		0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
		0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};

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

	

	namespace detail
	{
		template <uint32_t Bits>
		struct hash_state
		{
			static constexpr uint_fast16_t RATE = 1600 - Bits * 2;
			static constexpr uint_fast16_t BLOCK_SIZE = RATE / 8;
			static constexpr uint8_t HASH_SIZE = Bits / 64;
			static constexpr uint8_t MAX_PERMUTATION_SIZE = Bits / 64;

			uint64_t hash[HASH_STATE_SIZE];
			uint64_t message[MAX_HASH_RATE];
			uint8_t message_length;
		};

		template <uint32_t Divisor>
		SHA_CPP_INLINE_ALWAYS uint8_t fast_mod(uint8_t value)
		{
			static constexpr uint32_t PopCount = []()
			{
				constexpr uint32_t lookup[] =
				{
					0, 1, 1, 2,
					1, 2, 2, 3,
					1, 2, 2, 3,
					2, 3, 3, 4
				};

				uint32_t r = 0;
				for (uint32_t mask = Divisor; mask != 0; mask >>= 4)
					r += lookup[mask & 15];
				return r;
			}();

			if constexpr (PopCount == 1)
			{
				return value & (Divisor - 1);
			}
			else
			{
				if (value == Divisor)
					return 0;

				if (value < Divisor)
					return value;

				return value % Divisor;
			}
		}

		SHA_CPP_INLINE_ALWAYS bool is_8byte_aligned(void* ptr) noexcept
		{
			return ((size_t)ptr & 7) == 0;
		}

		SHA_CPP_INLINE_ALWAYS uint64_t to_little_endian(uint64_t value) noexcept
		{
#ifdef SHA_CPP_BIG_ENDIAN
			return (uint64_t)SHA_CPP_BSWAP64(value);
#else
			return value;
#endif
		}

		SHA_CPP_INLINE_ALWAYS void to_little_endian_copy(uint64_t* to, const uint64_t* from, size_t count) noexcept
		{
#ifdef SHA_CPP_BIG_ENDIAN
			count /= sizeof(uint64_t);
			const uint64_t* src = (const uint64_t*)from;
			const uint64_t* end = (const uint64_t*)((const char*)src + count);
			uint64_t* dst = (uint64_t*)to;
			while (src < end)
			{
				*dst = to_little_endian(*src);
				++dst;
				++src;
			}
#else
			(void)memcpy(to, from, count);
#endif
		}

		template <uint8_t Index>
		SHA_CPP_INLINE_ALWAYS uint64_t keccak_theta_xor(array_ref<const uint64_t, HASH_STATE_SIZE> state) noexcept
		{
			uint64_t r = state[Index];
			r ^= state[Index + 5];
			r ^= state[Index + 10];
			r ^= state[Index + 15];
			r ^= state[Index + 20];
			return r;
		}

		template <uint8_t Index>
		SHA_CPP_INLINE_ALWAYS void keccak_theta_step(array_ref<uint64_t, HASH_STATE_SIZE> state, array_ref<const uint64_t, 5> tmp) noexcept
		{
			for (uint8_t i = 0; i != 25; i += 5)
				state[Index + i] ^= tmp[Index];
		}

		SHA_CPP_INLINE_ALWAYS void keccak_theta(array_ref<uint64_t, HASH_STATE_SIZE> state) noexcept
		{
			const uint64_t tmp[] =
			{
				SHA_CPP_ROTL64(keccak_theta_xor<1>(state), 1) ^ keccak_theta_xor<4>(state),
				SHA_CPP_ROTL64(keccak_theta_xor<2>(state), 1) ^ keccak_theta_xor<0>(state),
				SHA_CPP_ROTL64(keccak_theta_xor<3>(state), 1) ^ keccak_theta_xor<1>(state),
				SHA_CPP_ROTL64(keccak_theta_xor<4>(state), 1) ^ keccak_theta_xor<2>(state),
				SHA_CPP_ROTL64(keccak_theta_xor<0>(state), 1) ^ keccak_theta_xor<3>(state)
			};

			keccak_theta_step<0>(state, tmp);
			keccak_theta_step<1>(state, tmp);
			keccak_theta_step<2>(state, tmp);
			keccak_theta_step<3>(state, tmp);
			keccak_theta_step<4>(state, tmp);
		}

		SHA_CPP_INLINE_ALWAYS void keccak_pi(array_ref<uint64_t, HASH_STATE_SIZE> state) noexcept
		{
			const uint64_t tmp = state[1];

			state[1] = state[6];
			state[6] = state[9];
			state[9] = state[22];
			state[22] = state[14];

			state[14] = state[20];
			state[20] = state[2];
			state[2] = state[12];
			state[12] = state[13];

			state[13] = state[19];
			state[19] = state[23];
			state[23] = state[15];
			state[15] = state[4];

			state[4] = state[24];
			state[24] = state[21];
			state[21] = state[8];
			state[8] = state[16];

			state[16] = state[5];
			state[5] = state[3];
			state[3] = state[18];
			state[18] = state[17];

			state[17] = state[11];
			state[11] = state[7];
			state[7] = state[10];
			state[10] = tmp;
		}

		template <uint8_t Index>
		SHA_CPP_INLINE_ALWAYS void keccak_chi_step(array_ref<uint64_t, HASH_STATE_SIZE> state) noexcept
		{
			const uint64_t tmp0 = state[0 + Index];
			const uint64_t tmp1 = state[1 + Index];
			state[0 + Index] ^= ~tmp1 & state[2 + Index];
			state[1 + Index] ^= ~state[2 + Index] & state[3 + Index];
			state[2 + Index] ^= ~state[3 + Index] & state[4 + Index];
			state[3 + Index] ^= ~state[4 + Index] & tmp0;
			state[4 + Index] ^= ~tmp0 & tmp1;
		}

		SHA_CPP_INLINE_ALWAYS void keccak_chi(array_ref<uint64_t, HASH_STATE_SIZE> state) noexcept
		{
			keccak_chi_step<0>(state);
			keccak_chi_step<5>(state);
			keccak_chi_step<10>(state);
			keccak_chi_step<15>(state);
			keccak_chi_step<20>(state);
		}

		SHA_CPP_INLINE_ALWAYS void sha3_permute(array_ref<uint64_t, HASH_STATE_SIZE> state) noexcept
		{
			for (uint8_t i = 0; i < KECCAK_ROUND_COUNT; i++)
			{
				keccak_theta(state);
				state[1] = SHA_CPP_ROTL64(state[1], 1);
				state[2] = SHA_CPP_ROTL64(state[2], 62);
				state[3] = SHA_CPP_ROTL64(state[3], 28);
				state[4] = SHA_CPP_ROTL64(state[4], 27);
				state[5] = SHA_CPP_ROTL64(state[5], 36);
				state[6] = SHA_CPP_ROTL64(state[6], 44);
				state[7] = SHA_CPP_ROTL64(state[7], 6);
				state[8] = SHA_CPP_ROTL64(state[8], 55);
				state[9] = SHA_CPP_ROTL64(state[9], 20);
				state[10] = SHA_CPP_ROTL64(state[10], 3);
				state[11] = SHA_CPP_ROTL64(state[11], 10);
				state[12] = SHA_CPP_ROTL64(state[12], 43);
				state[13] = SHA_CPP_ROTL64(state[13], 25);
				state[14] = SHA_CPP_ROTL64(state[14], 39);
				state[15] = SHA_CPP_ROTL64(state[15], 41);
				state[16] = SHA_CPP_ROTL64(state[16], 45);
				state[17] = SHA_CPP_ROTL64(state[17], 15);
				state[18] = SHA_CPP_ROTL64(state[18], 21);
				state[19] = SHA_CPP_ROTL64(state[19], 8);
				state[20] = SHA_CPP_ROTL64(state[20], 18);
				state[21] = SHA_CPP_ROTL64(state[21], 2);
				state[22] = SHA_CPP_ROTL64(state[22], 61);
				state[23] = SHA_CPP_ROTL64(state[23], 56);
				state[24] = SHA_CPP_ROTL64(state[24], 14);
				keccak_pi(state);
				keccak_chi(state);
				state[0] ^= KECCAK_ROUND_LOOKUP[i];
			}
		}

		template <uint8_t BlockSize>
		SHA_CPP_INLINE_ALWAYS void sha3_process_block(array_ref<uint64_t, HASH_STATE_SIZE> hash, const uint64_t* block) noexcept
		{
			constexpr uint8_t COUNT =
				BlockSize <= 72 ? 9 :
				BlockSize <= 104 ? 13 :
				BlockSize <= 136 ? 17 :
				BlockSize <= 144 ? 18 : 25;

			for (uint8_t i = 0; i != COUNT; ++i)
				hash[i] ^= to_little_endian(block[i]);

			sha3_permute(hash);
		}
	}



	template <uint32_t Bits>
	struct hasher : detail::hash_state<Bits>
	{
		using base = detail::hash_state<Bits>;

#ifdef SHA_CPP_DEBUG
		bool debug_finalized_flag;
#endif

		void add(const void* data, size_t size) noexcept
		{
#ifdef SHA_CPP_DEBUG
			assert(!debug_finalized_flag);
#endif
			constexpr uint8_t BLOCK_SIZE = base::BLOCK_SIZE;
			uint8_t* ptr = (uint8_t*)data;
			size_t index = base::message_length;
			base::message_length += (uint8_t)size;
			base::message_length = (uint8_t)detail::fast_mod<BLOCK_SIZE>(base::message_length);
			if (index != 0)
			{
				const size_t left = BLOCK_SIZE - index;
				(void)memcpy((uint8_t*)base::message + index, ptr, size < left ? size : left);
				if (size < left)
					return;
				detail::sha3_process_block<BLOCK_SIZE>(base::hash, base::message);
				ptr += left;
				size -= left;
			}
			while (size >= BLOCK_SIZE)
			{
				uint64_t* aligned_message_block;
				if (detail::is_8byte_aligned(ptr))
				{
					aligned_message_block = (uint64_t*)ptr;
				}
				else
				{
					(void)memcpy(base::message, ptr, BLOCK_SIZE);
					aligned_message_block = base::message;
				}
				detail::sha3_process_block<BLOCK_SIZE>(base::hash, aligned_message_block);
				ptr += BLOCK_SIZE;
				size -= BLOCK_SIZE;
			}
			if (size != 0)
			{
				(void)memcpy(base::message, ptr, size);
			}
		}

		template <size_t Size>
		void add_fixed(const void* data) noexcept
		{
#ifdef SHA_CPP_DEBUG
			assert(!debug_finalized_flag);
#endif
			constexpr uint8_t BLOCK_SIZE = base::BLOCK_SIZE;
			uint8_t* ptr = (uint8_t*)data;
			size_t size = Size;
			size_t index = base::message_length;
			base::message_length += (uint8_t)size;
			base::message_length = (uint8_t)detail::fast_mod<BLOCK_SIZE>(base::message_length);
			if (index != 0)
			{
				const size_t left = BLOCK_SIZE - index;
				(void)memcpy((uint8_t*)base::message + index, ptr, size < left ? size : left);
				if (size < left)
					return;
				detail::sha3_process_block<BLOCK_SIZE>(base::hash, base::message);
				ptr += left;
				size -= left;
			}
			while (size >= BLOCK_SIZE)
			{
				uint64_t* aligned_message_block = (uint64_t*)ptr;
				if (!detail::is_8byte_aligned(ptr))
				{
					(void)memcpy(base::message, ptr, BLOCK_SIZE);
					aligned_message_block = base::message;
				}
				detail::sha3_process_block<BLOCK_SIZE>(base::hash, aligned_message_block);
				ptr += BLOCK_SIZE;
				size -= BLOCK_SIZE;
			}
			if (size != 0)
			{
				(void)memcpy(base::message, ptr, size);
			}
		}
		
		void add(uint8_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }
		void add(uint16_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }
		void add(uint32_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }
		void add(uint64_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }

		void add(int8_t value) noexcept					{ this->add_fixed<sizeof(value)>(&value); }
		void add(int16_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }
		void add(int32_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }
		void add(int64_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }

		void add(float value) noexcept					{ this->add_fixed<sizeof(value)>(&value); }
		void add(double value) noexcept					{ this->add_fixed<sizeof(value)>(&value); }
		void add(long double value) noexcept			{ this->add_fixed<sizeof(value)>(&value); }

		void add(char value) noexcept					{ this->add_fixed<sizeof(value)>(&value); }
#if __cplusplus >= 202002L
		void add(char8_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }
#endif
		void add(char16_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }
		void add(char32_t value) noexcept				{ this->add_fixed<sizeof(value)>(&value); }
		
#ifdef SHA_CPP_STRING_VIEW
		void add(const std::string_view text) noexcept	{ this->add(text.data(), text.size()); }
#endif

		template <typename Collection>
		void add_collection(Collection&& values)
		{
			for (const auto& e : values)
				this->add_fixed<sizeof(std::remove_reference_t<decltype(e)>)>(e);
		}

		template <bool KeccakFinalizer = false>
		hash<Bits> get_result() noexcept
		{
#ifdef SHA_CPP_DEBUG
			assert(!debug_finalized_flag);
#endif
			hash<Bits> r = {};
			constexpr uint_fast16_t BLOCK_SIZE = base::BLOCK_SIZE;
			constexpr uint_fast16_t DIGEST_SIZE = 100 - BLOCK_SIZE / 2;
			static_assert(BLOCK_SIZE > DIGEST_SIZE);
			(void)memset((uint8_t*)base::message + base::message_length, 0, BLOCK_SIZE - base::message_length);
			constexpr uint64_t MASK = KeccakFinalizer ? 0x01 : 0x06;
			((uint8_t*)base::message)[base::message_length] |= MASK;
			((uint8_t*)base::message)[BLOCK_SIZE - 1] |= 0x80;
			detail::sha3_process_block<BLOCK_SIZE>(base::hash, base::message);
			detail::to_little_endian_copy(r.hash_data, base::hash, DIGEST_SIZE);
#ifdef SHA_CPP_DEBUG
			debug_finalized_flag = true;
#endif
			return r;
		}
	};
}