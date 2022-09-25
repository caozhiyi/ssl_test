#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string>

TEST(evp_aead_ctx, test1) {
    const u_char* key = "1234567891234567";
    const uint8_t key_len = strlen((const char*)key);
    const EVP_AEAD *aead = EVP_aead_aes_128_gcm();
    const u_char* nonce = "111111111111";
    const uint8_t nonce_len = strlen((const char*)aead);
    const u_char* data = "abcdefghijklmnopqrstuvwxyz";
    const uint8_t data_len = strlen((const char*)data);
    const u_char* ad = "111";
    const uint8_t ad_len = strlen((const char*)ad);
    
    EVP_AEAD_CTX *ctx = new EVP_AEAD_CTX;
    EVP_AEAD_CTX_cleanup(ctx);
    
    int ret = EVP_AEAD_CTX_init(ctx, aead, key, key_len, 0, nullptr);
    ASSERT_TRUE(ret == 1);

    uint8_t encrypt_buf[100] = {0};
    size_t encrypt_len = 0;
    ret = EVP_AEAD_CTX_seal(ctx, encrypt_buf, &encrypt_len, 100, nonce, nonce_len,
                                data, data_len, ad, ad_len);
    ASSERT_TRUE(ret == 1);

    uint8_t decrypt_buf[100] = {0};
    size_t decrypt_len = 0;
    ret = EVP_AEAD_CTX_open(ctx, decrypt_buf, &decrypt_len, 100, nonce, nonce_len,
                                encrypt_buf, encrypt_len, ad, ad_len);
    ASSERT_TRUE(ret == 1);

    ASSERT_EQ(std::string((const char*)data, data_len), std::string((const char*)decrypt_buf, decrypt_len));

    const u_char* new_key = "123456789abcdefg";
    const uint8_t new_key_len = strlen((const char*)key);
    EVP_AEAD_CTX_cleanup(ctx);
    ret = EVP_AEAD_CTX_init(ctx, aead, new_key, new_key_len, 0, nullptr);
    ASSERT_TRUE(ret == 1);

    ret = EVP_AEAD_CTX_seal(ctx, encrypt_buf, &encrypt_len, 100, nonce, nonce_len,
                                data, data_len, ad, ad_len);
    ASSERT_TRUE(ret == 1);

    ret = EVP_AEAD_CTX_open(ctx, decrypt_buf, &decrypt_len, 100, nonce, nonce_len,
                                encrypt_buf, encrypt_len, ad, ad_len);
    ASSERT_TRUE(ret == 1);

    ASSERT_EQ(std::string((const char*)data, data_len), std::string((const char*)decrypt_buf, decrypt_len));

    delete ctx;
}

TEST(evp_aead_ctx, test2) {
    const u_char* key = "1234567891234567";
    const uint8_t key_len = strlen((const char*)key);
    const EVP_AEAD *aead = EVP_aead_aes_128_gcm();
    const u_char* nonce = "111111111111";
    const uint8_t nonce_len = strlen((const char*)aead);
    const u_char* data = "abcdefghijklmnopqrstuvwxyz";
    const uint8_t data_len = strlen((const char*)data);
    const u_char* ad = "111";
    const uint8_t ad_len = strlen((const char*)ad);

    EVP_AEAD_CTX *ctx = EVP_AEAD_CTX_new(aead, key, key_len, 0);
    ASSERT_TRUE(ctx != nullptr);
    
    uint8_t encrypt_buf[100] = {0};
    size_t encrypt_len = 0;
    int ret = EVP_AEAD_CTX_seal(ctx, encrypt_buf, &encrypt_len, 100, nonce, nonce_len,
                                data, data_len, ad, ad_len);
    ASSERT_TRUE(ret == 1);

    uint8_t decrypt_buf[100] = {0};
    size_t decrypt_len = 0;
    ret = EVP_AEAD_CTX_open(ctx, decrypt_buf, &decrypt_len, 100, nonce, nonce_len,
                                encrypt_buf, encrypt_len, ad, ad_len);
    
    ASSERT_TRUE(ret == 1);

    EVP_AEAD_CTX_free(ctx);

    ASSERT_EQ(std::string((const char*)data, data_len), std::string((const char*)decrypt_buf, decrypt_len));
}