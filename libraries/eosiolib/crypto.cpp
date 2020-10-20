/**
 *  @file
 *  @copyright defined in eos/LICENSE
 */
#include "core/eosio/crypto.hpp"
#include "core/eosio/datastream.hpp"

extern "C" {
   struct __attribute__((aligned (16))) capi_checksum160 { uint8_t hash[20]; };
   struct __attribute__((aligned (16))) capi_checksum256 { uint8_t hash[32]; };
   struct __attribute__((aligned (16))) capi_checksum512 { uint8_t hash[64]; };
   __attribute__((eosio_wasm_import))
   void assert_sha256( const char* data, uint32_t length, const capi_checksum256* hash );

   __attribute__((eosio_wasm_import))
   void assert_sha1( const char* data, uint32_t length, const capi_checksum160* hash );

   __attribute__((eosio_wasm_import))
   void assert_sha512( const char* data, uint32_t length, const capi_checksum512* hash );

   __attribute__((eosio_wasm_import))
   void assert_ripemd160( const char* data, uint32_t length, const capi_checksum160* hash );

   __attribute__((eosio_wasm_import))
   void sha256( const char* data, uint32_t length, capi_checksum256* hash );

   __attribute__((eosio_wasm_import))
   void sha1( const char* data, uint32_t length, capi_checksum160* hash );

   __attribute__((eosio_wasm_import))
   void sha512( const char* data, uint32_t length, capi_checksum512* hash );

   __attribute__((eosio_wasm_import))
   void ripemd160( const char* data, uint32_t length, capi_checksum160* hash );

   __attribute__((eosio_wasm_import))
   int recover_key( const capi_checksum256* digest, const char* sig,
                    size_t siglen, char* pub, size_t publen );

   __attribute__((eosio_wasm_import))
   void assert_recover_key( const capi_checksum256* digest, const char* sig,
                            size_t siglen, const char* pub, size_t publen );

}

namespace {
   enum key_type : uint8_t {
      k1 = 0,
      r1 = 1
   };

   constexpr char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

   constexpr int8_t base58_map[256] = {
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6, 7,
      8,  -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1, 22, 23, 24, 25, 26,
      27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47,
      48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1,
   };

   void base58_to_binary(std::vector<uint8_t>& result, const std::string_view& s) {
      std::size_t offset = result.size();

      for (auto& src_digit : s) {
         int carry = base58_map[static_cast<uint8_t>(src_digit)];
         eosio::check(carry >= 0, "expected key");

         for (std::size_t i = offset; i < result.size(); ++i) {
            auto& result_byte = result[i];
            int x = static_cast<uint8_t>(result_byte) * 58 + carry;
            result_byte = x;
            carry = x >> 8;
         }

         if (carry) {
            result.push_back(static_cast<uint8_t>(carry));
         }
      }

      for (auto& src_digit : s) {
         if (src_digit == '1') {
            result.push_back(0);
         } else {
            break;
         }
      }

      std::reverse(result.begin() + offset, result.end());
   }

   std::string binary_to_base58(const std::vector<uint8_t>& bin) {
      std::string result("");

      for (auto byte : bin) {
         static_assert(sizeof(byte) == 1);
         int carry = static_cast<uint8_t>(byte);

         for (auto& result_digit : result) {
            int x = (base58_map[static_cast<size_t>(result_digit)] << 8) + carry;
            result_digit = base58_chars[x % 58];
            carry = x / 58;
         }

         while (carry) {
            result.push_back(base58_chars[carry % 58]);
            carry = carry / 58;
         }
      }

      for (auto byte : bin) {
         if (byte) {
            break;
         } else {
            result.push_back('1');
         }
      }

      std::reverse(result.begin(), result.end());
      return result;
   }

   std::vector<uint8_t> digest_suffix_ripemd160(std::vector<uint8_t> data, const std::string_view& suffix) {
      for (char digit : suffix) {
         data.push_back(digit);
      }

      eosio::checksum160 digest = eosio::ripemd160((char *) data.data(), data.size());
      auto digest_data = digest.extract_as_byte_array();

      return std::vector<uint8_t>{digest_data.begin(), digest_data.end()};
   }

   eosio::public_key convert_from_bin(const std::vector<uint8_t>& bin) {
      eosio::ecc_public_key data;
      std::copy(bin.begin() + 1, bin.end() - 4, data.begin());

      eosio::public_key result;

      if (bin.front() == key_type::k1) {
         result = eosio::public_key{std::in_place_index<0>, data};
      } else if (bin.front() == key_type::r1) {
         result = eosio::public_key{std::in_place_index<1>, data};
      }

      return result;
   }

   std::vector<uint8_t> convert_to_bin(const eosio::public_key& key) {
      eosio::ecc_public_key data;

      if (key.index() == key_type::k1) {
         data = std::get<key_type::k1>(key);
      } else if (key.index() == key_type::r1) {
         data = std::get<key_type::r1>(key);
      }

      std::vector<uint8_t> result(data.size());
      std::copy(data.begin(), data.end(), result.begin());

      return result;
   }

   eosio::public_key string_to_key(const std::string_view& s, const key_type& type, const std::string_view& suffix) {
      std::vector<uint8_t> whole;
      whole.push_back(uint8_t{type});

      base58_to_binary(whole, s);
      eosio::check(whole.size() > 5, "expected key");

      auto digest = digest_suffix_ripemd160(std::vector<uint8_t>{whole.begin() + 1, whole.end() - 4}, suffix);
      eosio::check(memcmp(digest.data(), whole.data() + whole.size() - 4, 4) == 0, "invalid key");

      return convert_from_bin(whole);
   }

   std::string key_to_string(const eosio::public_key& key, const std::string_view& suffix, const std::string& prefix) {
      auto whole = convert_to_bin(key);

      auto digest = digest_suffix_ripemd160(whole, suffix);
      whole.insert(whole.end(), digest.data(), digest.data() + 4);

      return prefix + binary_to_base58(whole);
   }
} // namespace

namespace eosio {

   std::string public_key_to_string(const public_key& key) {
      std::string result;

      if (key.index() == key_type::k1) {
         result = key_to_string(key, "K1", "PUB_K1_");
      } else if (key.index() == key_type::r1) {
         result = key_to_string(key, "R1", "PUB_R1_");
      } else {
         eosio::check(false, "expected public key");
      }

      return result;
   }

   public_key public_key_from_string(const std::string_view& s) {
      public_key result;

      if (s.substr(0, 3) == "EOS") {
         result = string_to_key(s.substr(3), key_type::k1, "");
      } else if (s.substr(0, 7) == "PUB_K1_") {
         result = string_to_key(s.substr(7), key_type::k1, "K1");
      } else if (s.substr(0, 7) == "PUB_R1_") {
         result = string_to_key(s.substr(7), key_type::r1, "R1");
      } else {
         eosio::check(false, "expected public key");
      }

      return result;
   }

   void assert_sha256( const char* data, uint32_t length, const eosio::checksum256& hash ) {
      auto hash_data = hash.extract_as_byte_array();
      ::assert_sha256( data, length, reinterpret_cast<const ::capi_checksum256*>(hash_data.data()) );
   }

   void assert_sha1( const char* data, uint32_t length, const eosio::checksum160& hash ) {
      auto hash_data = hash.extract_as_byte_array();
      ::assert_sha1( data, length, reinterpret_cast<const ::capi_checksum160*>(hash_data.data()) );
   }

   void assert_sha512( const char* data, uint32_t length, const eosio::checksum512& hash ) {
      auto hash_data = hash.extract_as_byte_array();
      ::assert_sha512( data, length, reinterpret_cast<const ::capi_checksum512*>(hash_data.data()) );
   }

   void assert_ripemd160( const char* data, uint32_t length, const eosio::checksum160& hash ) {
      auto hash_data = hash.extract_as_byte_array();
      ::assert_ripemd160( data, length, reinterpret_cast<const ::capi_checksum160*>(hash_data.data()) );
   }

   eosio::checksum256 sha256( const char* data, uint32_t length ) {
      ::capi_checksum256 hash;
      ::sha256( data, length, &hash );
      return {hash.hash};
   }

   eosio::checksum160 sha1( const char* data, uint32_t length ) {
      ::capi_checksum160 hash;
      ::sha1( data, length, &hash );
      return {hash.hash};
   }

   eosio::checksum512 sha512( const char* data, uint32_t length ) {
      ::capi_checksum512 hash;
      ::sha512( data, length, &hash );
      return {hash.hash};
   }

   eosio::checksum160 ripemd160( const char* data, uint32_t length ) {
      ::capi_checksum160 hash;
      ::ripemd160( data, length, &hash );
      return {hash.hash};
   }

   eosio::public_key recover_key( const eosio::checksum256& digest, const eosio::signature& sig ) {
      auto digest_data = digest.extract_as_byte_array();

      auto sig_data = eosio::pack(sig);

      char optimistic_pubkey_data[256];
      size_t pubkey_size = ::recover_key( reinterpret_cast<const capi_checksum256*>(digest_data.data()),
                                          sig_data.data(), sig_data.size(),
                                          optimistic_pubkey_data, sizeof(optimistic_pubkey_data) );

      eosio::public_key pubkey;
      if ( pubkey_size <= sizeof(optimistic_pubkey_data) ) {
         eosio::datastream<const char*> pubkey_ds( optimistic_pubkey_data, pubkey_size );
         pubkey_ds >> pubkey;
      } else {
         constexpr static size_t max_stack_buffer_size = 512;
         void* pubkey_data = (max_stack_buffer_size < pubkey_size) ? malloc(pubkey_size) : alloca(pubkey_size);

         ::recover_key( reinterpret_cast<const capi_checksum256*>(digest_data.data()),
                        sig_data.data(), sig_data.size(),
                        reinterpret_cast<char*>(pubkey_data), pubkey_size );
         eosio::datastream<const char*> pubkey_ds( reinterpret_cast<const char*>(pubkey_data), pubkey_size );
         pubkey_ds >> pubkey;

         if( max_stack_buffer_size < pubkey_size ) {
            free(pubkey_data);
         }
      }
      return pubkey;
   }

   void assert_recover_key( const eosio::checksum256& digest, const eosio::signature& sig, const eosio::public_key& pubkey ) {
      auto digest_data = digest.extract_as_byte_array();

      auto sig_data = eosio::pack(sig);
      auto pubkey_data = eosio::pack(pubkey);

      ::assert_recover_key( reinterpret_cast<const capi_checksum256*>(digest_data.data()),
                            sig_data.data(), sig_data.size(),
                            pubkey_data.data(), pubkey_data.size() );
   }

}
