/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/cipher.cpp
 * Copyright (C) 2019 Emilien Kia <emilien.kia+dev@gmail.com>
 *
 * libcexxy is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libcexxy is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.";
 */

#include "cipher.hpp"

#include <openssl/evp.h>

#include <exception>
#include <functional>
#include <map>
#include <string>

#include <iostream>


namespace cxy
{
namespace security
{

enum CIPHER_CHAIN_MODE
{
    CCMODE_NONE,
    CCMODE_CBC,
    CCMODE_CFB,
    CCMODE_CFB1,
    CCMODE_CFB8,
    CCMODE_CTR,
    CCMODE_CTS,
    CCMODE_ECB,
    CCMODE_GCM,
    CCMODE_OFB,
};

namespace openssl
{

class evm_cipher : public cipher
{
private:
    EVP_CIPHER_CTX *_ctx = nullptr;

public:
    static std::shared_ptr<cipher> get(const std::string& algorithm, const std::string& mode, const std::string& padding, const cxy::security::key* key, const std::vector<uint8_t/*std::byte*/>& iv, bool encrypt);

    evm_cipher(const EVP_CIPHER *type, bool padding, const unsigned char *key, const unsigned char *iv, bool enc);
    virtual ~evm_cipher();

    virtual cipher& update_aad(const void* data, size_t sz) override;
    virtual std::vector<uint8_t/*std::byte*/> update(const void* data, size_t sz) override;

    virtual std::vector<uint8_t/*std::byte*/> finalize() override;
    virtual std::vector<uint8_t/*std::byte*/> finalize(const void* data, size_t sz) override;
};

struct symetric_cipher_desc {
    std::string name;
    std::string mode;
    int key_size;
    int iv_size;
    std::function<const EVP_CIPHER*()> fct;
};

symetric_cipher_desc _sym_ciphers [] = {
    {"AES", "CBC", 16, 16, EVP_aes_128_cbc },
    {"AES_128", "CBC", 16, 16, EVP_aes_128_cbc },
    {"AES", "CBC", 24, 16, EVP_aes_192_cbc },
    {"AES_192", "CBC", 24, 16, EVP_aes_192_cbc },
    {"AES", "CBC", 32, 16, EVP_aes_256_cbc },
    {"AES_256", "CBC", 32, 16, EVP_aes_256_cbc },
    {"AES", "CFB", 16, 16, EVP_aes_128_cfb },
    {"AES_128", "CFB", 16, 16, EVP_aes_128_cfb },
    {"AES", "CFB", 24, 16, EVP_aes_192_cfb },
    {"AES_192", "CFB", 24, 16, EVP_aes_192_cfb },
    {"AES", "CFB", 32, 16, EVP_aes_256_cfb },
    {"AES_256", "CFB", 32, 16, EVP_aes_256_cfb },
    {"AES", "CFB1", 16, 16, EVP_aes_128_cfb1 },
    {"AES_128", "CFB1", 16, 16, EVP_aes_128_cfb1 },
    {"AES", "CFB1", 24, 16, EVP_aes_192_cfb1 },
    {"AES_192", "CFB1", 24, 16, EVP_aes_192_cfb1 },
    {"AES", "CFB1", 32, 16, EVP_aes_256_cfb1 },
    {"AES_256", "CFB1", 32, 16, EVP_aes_256_cfb1 },
    {"AES", "CFB8", 16, 16, EVP_aes_128_cfb8 },
    {"AES_128", "CFB8", 16, 16, EVP_aes_128_cfb8 },
    {"AES", "CFB8", 24, 16, EVP_aes_192_cfb8 },
    {"AES_192", "CFB8", 24, 16, EVP_aes_192_cfb8 },
    {"AES", "CFB8", 32, 16, EVP_aes_256_cfb8 },
    {"AES_256", "CFB8", 32, 16, EVP_aes_256_cfb8 },
    {"AES", "CFB128", 16, 16, EVP_aes_128_cfb128 },
    {"AES_128", "CFB128", 16, 16, EVP_aes_128_cfb128 },
    {"AES", "CFB128", 24, 16, EVP_aes_192_cfb128 },
    {"AES_192", "CFB128", 24, 16, EVP_aes_192_cfb128 },
    {"AES", "CFB128", 32, 16, EVP_aes_256_cfb128 },
    {"AES_256", "CFB128", 32, 16, EVP_aes_256_cfb128 },
    {"AES", "CTR", 16, 16, EVP_aes_128_ctr },
    {"AES_128", "CTR", 16, 16, EVP_aes_128_ctr },
    {"AES", "CTR", 24, 16, EVP_aes_192_ctr },
    {"AES_192", "CTR", 24, 16, EVP_aes_192_ctr },
    {"AES", "CTR", 32, 16, EVP_aes_256_ctr },
    {"AES_256", "CTR", 32, 16, EVP_aes_256_ctr },
    {"AES", "ECB", 16,  0, EVP_aes_128_ecb },
    {"AES_128", "ECB",  0, 16, EVP_aes_128_ecb },
    {"AES", "ECB", 24,  0, EVP_aes_192_ecb },
    {"AES_192", "ECB",  0, 16, EVP_aes_192_ecb },
    {"AES", "ECB", 32,  0, EVP_aes_256_ecb },
    {"AES_256", "ECB",  0, 16, EVP_aes_256_ecb },
    {"AES", "OFB", 16, 16, EVP_aes_128_ofb },
    {"AES_128", "OFB", 16, 16, EVP_aes_128_ofb },
    {"AES", "OFB", 24, 16, EVP_aes_192_ofb },
    {"AES_192", "OFB", 24, 16, EVP_aes_192_ofb },
    {"AES", "OFB", 32, 16, EVP_aes_256_ofb },
    {"AES_256", "OFB", 32, 16, EVP_aes_256_ofb }

};



std::shared_ptr<cipher> evm_cipher::get(const std::string& algorithm, const std::string& mode, const std::string& padding, const cxy::security::key* key, const std::vector<uint8_t/*std::byte*/>& iv, bool encrypt)
{
    bool pad;
    if(padding.empty()) {
        pad = true;
    } else if(padding==CXY_CIPHER_NO_PADDING) {
        pad = false;
    } else  if(padding==CXY_CIPHER_PKCS5_PADDING || padding==CXY_CIPHER_PKCS7_PADDING ) {
        //pad = padding;
        // PKCS#5 is a substract of PKCS#7 padding., use them as an alias for legacy compatibility
        // See https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
        pad = true;
    } else {
        std::cerr << "Unsupported padding : " << padding << std::endl;
        return nullptr; // No supported padding method
    }

    // Assume a key is present
    if(key == nullptr) {
        return nullptr; // A key is mandatory
    }

    const cxy::security::secret_key* seckey = dynamic_cast<const cxy::security::secret_key*>(key);

    // TODO normalize params

    for(auto& cdesc : _sym_ciphers) {
        if(algorithm==cdesc.name && mode==cdesc.mode && seckey->size()==cdesc.key_size) {
            auto c = cdesc.fct();
            int ivsz = EVP_CIPHER_iv_length(c);
            if(iv.size()==ivsz) {
                return std::make_shared<evm_cipher>(c, pad, seckey->value().data(), iv.data(), encrypt);
            } else {
                std::cerr << "Bad IV size (" << iv.size() << " / " << ivsz << " expected)" << std::endl;
                return nullptr;
            }
        }
    }

    std::cerr << "No corresponding cipher." << std::endl;
    return nullptr;
}

evm_cipher::evm_cipher(const EVP_CIPHER *type, bool padding, const unsigned char *key, const unsigned char *iv, bool enc)
{
    _ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(_ctx, type, key, iv, enc?1:0)) {
        std::cerr << "Error when instatiating cipher." << std::endl;
        // TODO throw exception.
    }

    if(!EVP_CIPHER_CTX_set_padding(_ctx, padding ? 1 : 0)) {
        std::cerr << "Error when setting padding to cipher." << std::endl;
        // TODO throw exception.
    }
}

evm_cipher::~evm_cipher()
{
    if(_ctx!=nullptr) {
        EVP_CIPHER_CTX_free(_ctx);
        _ctx = nullptr;
    }
}

cipher& evm_cipher::update_aad(const void* data, size_t sz)
{
    if(!EVP_CipherUpdate(_ctx, nullptr, nullptr, (const unsigned char*)data, sz)) {
        std::cerr << "Error while streaming aad data to cipher" << std::endl;
    }
}

std::vector<uint8_t/*std::byte*/> evm_cipher::update(const void* data, size_t sz)
{
    std::vector<uint8_t/*std::byte*/> res;
    unsigned char buffer[1024 + EVP_MAX_BLOCK_LENGTH];
    int len;
    const unsigned char* ptr = (const unsigned char*)data;

    while(sz>0) {
        int s = std::min((int)sz, 1024);
        if(!EVP_CipherUpdate(_ctx, buffer, &len, ptr, s)) {
            std::cerr << "Error while streaming data to cipher" << std::endl;
        }
        res.insert(res.end(), buffer, buffer+len);
        sz -= s;
        ptr += s;
    }

    return res;
}

std::vector<uint8_t/*std::byte*/> evm_cipher::finalize()
{
    std::vector<uint8_t/*std::byte*/> res;
    unsigned char buffer[EVP_MAX_BLOCK_LENGTH];
    int len;

    if(!EVP_CipherFinal_ex(_ctx, buffer, &len)) {
        std::cerr << "Error while streaming data to cipher" << std::endl;
    }
    res.insert(res.end(), buffer, buffer+len);

    return res;
}

std::vector<uint8_t/*std::byte*/> evm_cipher::finalize(const void* data, size_t sz)
{
    std::vector<uint8_t/*std::byte*/> res;
    unsigned char buffer[1024 + EVP_MAX_BLOCK_LENGTH];
    int len;
    const unsigned char* ptr = (const unsigned char*)data;

    while(sz>0) {
        int s = std::min((int)sz, 1024);
        if(!EVP_CipherUpdate(_ctx, buffer, &len, ptr, s)) {
            std::cerr << "Error while streaming data to cipher" << std::endl;
        }
        res.insert(res.end(), buffer, buffer+len);
        sz -= s;
        ptr += s;
    }

    if(!EVP_CipherFinal_ex(_ctx, buffer, &len)) {
        std::cerr << "Error while streaming data to cipher" << std::endl;
    }
    res.insert(res.end(), buffer, buffer+len);

    return res;
}


} // namespace cxy::security::openssl



//
// cipher_builder
//

cipher_builder& cipher_builder::algorithm(const std::string& algo)
{
    _algo = algo;
    return *this;
}

cipher_builder& cipher_builder::mode(const std::string& mode)
{
    _mode = mode;
    return *this;

}

cipher_builder& cipher_builder::padding(const std::string& padding)
{
    _pad = padding;
    return *this;
}

cipher_builder& cipher_builder::key(cxy::security::key& key)
{
    _key = &key;
    return *this;

}

cipher_builder& cipher_builder::initial_vector(const std::vector<uint8_t/*std::byste*/> iv)
{
    _iv = iv;
    return *this;
}

std::shared_ptr<cipher> cipher_builder::encrypt()
{
    return openssl::evm_cipher::get(_algo, _mode, _pad, _key, _iv, true);
}

std::shared_ptr<cipher> cipher_builder::decrypt()
{
    return openssl::evm_cipher::get(_algo, _mode, _pad, _key, _iv, false);
}


}} // namespace cxy::security
