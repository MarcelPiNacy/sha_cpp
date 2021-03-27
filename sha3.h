#pragma once
#include "sha_common.h"

namespace sha_cpp
{
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

	namespace detail::sha3
	{
		static constexpr uint8_t HASH_STATE_SIZE = 25;
		static constexpr uint8_t MAX_HASH_RATE = 24;

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

		template <uint8_t BlockSize>
		SHA_CPP_INLINE_ALWAYS void process_block(array_ref<uint64_t, HASH_STATE_SIZE> hash, const uint64_t* block) noexcept
		{
			constexpr uint8_t Count =
				BlockSize <= 72 ? 9 :
				BlockSize <= 104 ? 13 :
				BlockSize <= 136 ? 17 :
				BlockSize <= 144 ? 18 : 25;

			for (uint8_t i = 0; i != Count; ++i)
				hash[i] ^= to_little_endian(block[i]);

			for (uint8_t i = 0; i < KECCAK_ROUND_COUNT; i++)
			{
				keccak_theta(hash);
				hash[1]  = SHA_CPP_ROTL64(hash[1], 1);
				hash[2]  = SHA_CPP_ROTL64(hash[2], 62);
				hash[3]  = SHA_CPP_ROTL64(hash[3], 28);
				hash[4]  = SHA_CPP_ROTL64(hash[4], 27);
				hash[5]  = SHA_CPP_ROTL64(hash[5], 36);
				hash[6]  = SHA_CPP_ROTL64(hash[6], 44);
				hash[7]  = SHA_CPP_ROTL64(hash[7], 6);
				hash[8]  = SHA_CPP_ROTL64(hash[8], 55);
				hash[9]  = SHA_CPP_ROTL64(hash[9], 20);
				hash[10] = SHA_CPP_ROTL64(hash[10], 3);
				hash[11] = SHA_CPP_ROTL64(hash[11], 10);
				hash[12] = SHA_CPP_ROTL64(hash[12], 43);
				hash[13] = SHA_CPP_ROTL64(hash[13], 25);
				hash[14] = SHA_CPP_ROTL64(hash[14], 39);
				hash[15] = SHA_CPP_ROTL64(hash[15], 41);
				hash[16] = SHA_CPP_ROTL64(hash[16], 45);
				hash[17] = SHA_CPP_ROTL64(hash[17], 15);
				hash[18] = SHA_CPP_ROTL64(hash[18], 21);
				hash[19] = SHA_CPP_ROTL64(hash[19], 8);
				hash[20] = SHA_CPP_ROTL64(hash[20], 18);
				hash[21] = SHA_CPP_ROTL64(hash[21], 2);
				hash[22] = SHA_CPP_ROTL64(hash[22], 61);
				hash[23] = SHA_CPP_ROTL64(hash[23], 56);
				hash[24] = SHA_CPP_ROTL64(hash[24], 14);
				keccak_pi(hash);
				keccak_chi(hash);
				hash[0] ^= KECCAK_ROUND_LOOKUP[i];
			}
		}
	}



	template <uint32_t Bits>
	struct sha3_hasher : detail::sha3::hash_state<Bits>
	{
		using base = detail::sha3::hash_state<Bits>;

#ifdef SHA_CPP_DEBUG
		bool debug_finalized_flag;
#endif

		void add(const void* data, size_t size) noexcept
		{
#ifdef SHA_CPP_DEBUG
			assert(!debug_finalized_flag);
#endif
			constexpr uint8_t BlockSize = base::BLOCK_SIZE;
			uint8_t* ptr = (uint8_t*)data;
			size_t index = base::message_length;
			base::message_length += (uint8_t)size;
			base::message_length = (uint8_t)detail::sha3::fast_mod<BlockSize>(base::message_length);
			if (index != 0)
			{
				const size_t left = BlockSize - index;
				(void)memcpy((uint8_t*)base::message + index, ptr, size < left ? size : left);
				if (size < left)
					return;
				detail::sha3::process_block<BlockSize>(base::hash, base::message);
				ptr += left;
				size -= left;
			}
			while (size >= BlockSize)
			{
				uint64_t* aligned_message_block;
				if (detail::sha3::is_8byte_aligned(ptr))
				{
					aligned_message_block = (uint64_t*)ptr;
				}
				else
				{
					(void)memcpy(base::message, ptr, BlockSize);
					aligned_message_block = base::message;
				}
				detail::sha3::process_block<BlockSize>(base::hash, aligned_message_block);
				ptr += BlockSize;
				size -= BlockSize;
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
			constexpr uint8_t BlockSize = base::BLOCK_SIZE;
			uint8_t* ptr = (uint8_t*)data;
			size_t size = Size;
			size_t index = base::message_length;
			base::message_length += (uint8_t)size;
			base::message_length = (uint8_t)detail::sha3::fast_mod<BlockSize>(base::message_length);
			if (index != 0)
			{
				const size_t left = BlockSize - index;
				(void)memcpy((uint8_t*)base::message + index, ptr, size < left ? size : left);
				if (size < left)
					return;
				detail::sha3::process_block<BlockSize>(base::hash, base::message);
				ptr += left;
				size -= left;
			}
			while (size >= BlockSize)
			{
				uint64_t* aligned_message_block = (uint64_t*)ptr;
				if (!detail::sha3::is_8byte_aligned(ptr))
				{
					(void)memcpy(base::message, ptr, BlockSize);
					aligned_message_block = base::message;
				}
				detail::sha3::process_block<BlockSize>(base::hash, aligned_message_block);
				ptr += BlockSize;
				size -= BlockSize;
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
			constexpr uint_fast16_t BlockSize = base::BlockSize;
			constexpr uint_fast16_t DigestSize = 100 - BlockSize / 2;
			static_assert(BlockSize > DigestSize);
			(void)memset((uint8_t*)base::message + base::message_length, 0, BlockSize - base::message_length);
			constexpr uint64_t MASK = KeccakFinalizer ? 0x01 : 0x06;
			((uint8_t*)base::message)[base::message_length] |= MASK;
			((uint8_t*)base::message)[BlockSize - 1] |= 0x80;
			detail::sha3::process_block<BlockSize>(base::hash, base::message);
			detail::sha3::to_little_endian_copy(r.hash_data, base::hash, DigestSize);
#ifdef SHA_CPP_DEBUG
			debug_finalized_flag = true;
#endif
			return r;
		}
	};
}