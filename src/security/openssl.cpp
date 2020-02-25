/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/openssl.cpp
 * Copyright (C) 2020 Emilien Kia <emilien.kia+dev@gmail.com>
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

#include "openssl.hpp"

#include "exceptions.hpp"

#include <iostream>
#include <functional>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <openssl/err.h>

// https://crypto.stackexchange.com/questions/32692/what-is-the-typical-block-size-in-rsa/32694#32694
// https://crypto.stackexchange.com/questions/2074/rsa-oaep-input-parameters


namespace cxy
{
namespace security
{
namespace openssl
{

cxy::math::big_integer bn2bi(const BIGNUM *bn)
{
    cxy::math::big_integer res;
    if(bn!=nullptr)
    {
        int sz = BN_num_bytes(bn);
        if(sz>0)
        {
            uint8_t*  buffer = new uint8_t[sz];
            int s = BN_bn2bin(bn, buffer);
            if(s>0)
            {
                res.assign<uint8_t>(buffer, sz, cxy::math::big_integer::WORD_MOST_SIGNIFICANT_FIRST, cxy::math::big_integer::MOST_SIGNIFICANT_FIRST);
            }
            delete [] buffer;
        }
    }
    return res;
}

BIGNUM* bi2bn(const cxy::math::big_integer& bi, BIGNUM* bn)
{
    std::vector<uint8_t> buffer = bi.get_vector<uint8_t>(cxy::math::big_integer::WORD_MOST_SIGNIFICANT_FIRST, cxy::math::big_integer::MOST_SIGNIFICANT_FIRST);
    if(!buffer.empty())
    {
        return BN_bin2bn(buffer.data(), buffer.size(), bn);
    }
    else
    {
        if(bn != nullptr)
            BN_zero(bn);
        return bn;
    }
}



//
// EVP
//



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



std::shared_ptr<cipher> evp_cipher::get(const std::string& algorithm, const std::string& mode, const std::string& padding, const cxy::security::key* key, const std::vector<uint8_t/*std::byte*/>& iv, bool encrypt)
{
    const cxy::security::secret_key* seckey = dynamic_cast<const cxy::security::secret_key*>(key);
    // Assume a key is present
    if(seckey == nullptr) {
        return nullptr; // A key is mandatory
    }

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
        std::ostringstream stm;
        stm << "Unsupported padding : " << padding;
        throw no_such_padding_exception(stm.str());
    }

    // TODO normalize params

    for(auto& cdesc : _sym_ciphers) {
        if(algorithm==cdesc.name && mode==cdesc.mode && seckey->size()==cdesc.key_size) {
            auto c = cdesc.fct();
            int ivsz = EVP_CIPHER_iv_length(c);
            if(iv.size()==ivsz) {
                return std::make_shared<evp_cipher>(c, pad, seckey->value().data(), iv.data(), encrypt);
            } else {
                std::ostringstream stm;
                stm << "Bad IV size (" << iv.size() << " / " << ivsz << " expected)";
                throw invalid_key_exception(stm.str());
            }
        }
    }

    throw no_such_algorithm_exception("No corresponding cipher.");
}

evp_cipher::evp_cipher(const EVP_CIPHER *type, bool padding, const unsigned char *key, const unsigned char *iv, bool enc)
{
    _ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(_ctx, type, key, iv, enc?1:0)) {
        throw invalid_key_exception("Error when instatiating cipher.");
    }

    if(!EVP_CIPHER_CTX_set_padding(_ctx, padding ? 1 : 0)) {
        throw invalid_key_exception("Error when setting padding to cipher.");
    }
}

evp_cipher::~evp_cipher()
{
    if(_ctx!=nullptr) {
        EVP_CIPHER_CTX_free(_ctx);
        _ctx = nullptr;
    }
}

cipher& evp_cipher::update_aad(const void* data, size_t sz)
{
    if(!EVP_CipherUpdate(_ctx, nullptr, nullptr, (const unsigned char*)data, sz)) {
        throw invalid_key_exception("Error while streaming aad data to cipher.");
    }
    return *this;
}

std::vector<uint8_t/*std::byte*/> evp_cipher::update(const void* data, size_t sz)
{
    std::vector<uint8_t/*std::byte*/> res;
    unsigned char buffer[1024 + EVP_MAX_BLOCK_LENGTH];
    int len;
    const unsigned char* ptr = (const unsigned char*)data;

    while(sz>0) {
        int s = std::min((int)sz, 1024);
        if(!EVP_CipherUpdate(_ctx, buffer, &len, ptr, s)) {
            throw invalid_key_exception("Error while streaming data to cipher.");
        }
        res.insert(res.end(), buffer, buffer+len);
        sz -= s;
        ptr += s;
    }

    return res;
}

std::vector<uint8_t/*std::byte*/> evp_cipher::finalize()
{
    std::vector<uint8_t/*std::byte*/> res;
    unsigned char buffer[EVP_MAX_BLOCK_LENGTH];
    int len;

    if(!EVP_CipherFinal_ex(_ctx, buffer, &len)) {
        throw invalid_key_exception("Error while streaming data to cipher.");
    }
    res.insert(res.end(), buffer, buffer+len);

    return res;
}

std::vector<uint8_t/*std::byte*/> evp_cipher::finalize(const void* data, size_t sz)
{
    std::vector<uint8_t/*std::byte*/> res;
    unsigned char buffer[1024 + EVP_MAX_BLOCK_LENGTH];
    int len;
    const unsigned char* ptr = (const unsigned char*)data;

    while(sz>0) {
        int s = std::min((int)sz, 1024);
        if(!EVP_CipherUpdate(_ctx, buffer, &len, ptr, s)) {
            throw invalid_key_exception("Error while streaming data to cipher.");
        }
        res.insert(res.end(), buffer, buffer+len);
        sz -= s;
        ptr += s;
    }

    if(!EVP_CipherFinal_ex(_ctx, buffer, &len)) {
        throw invalid_key_exception("Error while finalizing ciphering.");
    }
    res.insert(res.end(), buffer, buffer+len);

    return res;
}


//
// EVP PKEY
//

std::shared_ptr<cipher> evp_pkey_cipher::get(const std::string& algorithm, const std::string& padding, const cxy::security::key* key, bool encrypt) {
    // Assume a key is present
    if(key == nullptr) {
        return nullptr; // A key is mandatory
    }

    //
    // RSA
    //
    const rsa_key* rsakey = dynamic_cast<const rsa_key*>(key);
    if(rsakey!=nullptr) {
        if(!algorithm.empty() && algorithm!=CXY_KEY_RSA) {
            throw invalid_key_exception("Key type mismatch.");
        }

        const ossl_rsa_key* orsakey = dynamic_cast<const ossl_rsa_key*>(rsakey);
        if(orsakey==nullptr) {
            // TODO convert key to openssl
            throw security_exception("Not implemented yet");
        }

        EVP_PKEY *pkey = EVP_PKEY_new();
        if(!EVP_PKEY_set1_RSA(pkey, const_cast<RSA*>(orsakey->get()))) {
            throw invalid_key_exception("Cannot assign RSA key");
        }

        EVP_PKEY_PADDING_MODE padmode = RSA_PAD_NONE;
        if(padding==CXY_CIPHER_PKCS1_PADDING) {
            padmode = RSA_PAD_PKCS1;
        } else if(padding==CXY_CIPHER_PKCS1_OAEP_PADDING) {
            padmode = RSA_PAD_OAEP;
        } else if(!padding.empty() && padding!=CXY_CIPHER_NO_PADDING) {
            std::ostringstream stm;
            stm << "Unsupported padding mode '" << padding << "' for RSA.";
            throw no_such_padding_exception(stm.str());
        }

        return std::dynamic_pointer_cast<cipher>(std::make_shared<evp_pkey_cipher>(pkey, padmode, encrypt));
    }

    throw no_such_algorithm_exception();
}

evp_pkey_cipher::evp_pkey_cipher(EVP_PKEY *pkey, EVP_PKEY_PADDING_MODE padding, bool enc) : _encode(enc) {
    _ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if(!_ctx) {
        throw invalid_key_exception(/*...*/);
    }

    if((enc ? EVP_PKEY_encrypt_init : EVP_PKEY_decrypt_init)(_ctx) <= 0) {
        throw invalid_key_exception(/*...*/);
    }

    switch(padding) {
        case RSA_PAD_NONE:
            if(EVP_PKEY_CTX_set_rsa_padding(_ctx, RSA_NO_PADDING) <= 0) {
                throw invalid_key_exception(/*...*/);
            }
            break;
        case RSA_PAD_PKCS1:
            if(EVP_PKEY_CTX_set_rsa_padding(_ctx, RSA_PKCS1_PADDING) <= 0) {
                throw invalid_key_exception(/*...*/);
            }
            break;
        case RSA_PAD_OAEP:
            if(EVP_PKEY_CTX_set_rsa_padding(_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
                throw invalid_key_exception(/*...*/);
            }
            break;
    }
}

evp_pkey_cipher::~evp_pkey_cipher() {
    if(_ctx!=nullptr) {
        EVP_PKEY_CTX_free(_ctx);
        _ctx = nullptr;
    }
}

cipher& evp_pkey_cipher::update_aad(const void* data, size_t sz) {
    // TODO / Do nothing
    return *this;
}

std::vector<uint8_t/*std::byte*/> evp_pkey_cipher::update(const void* data, size_t sz) {
    throw invalid_key_exception("Update not supported for RSA ciphering");
}

std::vector<uint8_t/*std::byte*/> evp_pkey_cipher::finalize() {
    throw invalid_key_exception("Empty finalize not supported for RSA ciphering");
}

std::vector<uint8_t/*std::byte*/> evp_pkey_cipher::finalize(const void* data, size_t sz) {
    size_t outlen;
    if((_encode ? EVP_PKEY_encrypt : EVP_PKEY_decrypt)(_ctx, nullptr, &outlen, (const uint8_t*)data, sz) <= 0) {
        std::ostringstream stm;
        stm << "Problem in " << (_encode ? "encrypt" : "decrypt") << " size calculation.";
        throw invalid_key_exception(stm.str());
    }

    char errbuff[1024];

    std::vector<uint8_t> res(outlen);
    int r = (_encode ? EVP_PKEY_encrypt : EVP_PKEY_decrypt)(_ctx, res.data(), &outlen, (const uint8_t*)data, sz);
    if(r <= 0) {
        ERR_error_string_n(ERR_get_error() , errbuff, 1024);
        std::ostringstream stm;
        stm << "Problem in " << (_encode ? "encrypting" : "decrypting") << " : " << r << " : " << errbuff;
        throw invalid_key_exception(stm.str());
    }
    res.resize(outlen);
    return res;
}




//
// RSA
//

inline RSA_sptr make_rsa(RSA* rsa) {
    return RSA_sptr(rsa, RSA_free);
}



//
// ossl_rsa_key
//

ossl_rsa_key::ossl_rsa_key(RSA* rsa) :
_rsa(make_rsa(rsa))
{
}

cxy::math::big_integer ossl_rsa_key::modulus() const {
    return bn2bi(RSA_get0_n(_rsa.get()));
}



//
// ossl_rsa_public_key
//

ossl_rsa_public_key::ossl_rsa_public_key(RSA* rsa) :
ossl_rsa_key(rsa)
{
}

cxy::math::big_integer ossl_rsa_public_key::public_exponent() const {
    return bn2bi(RSA_get0_e(_rsa.get()));
}

//
// ossl_rsa_private_key
//

ossl_rsa_private_key::ossl_rsa_private_key(RSA* rsa) :
ossl_rsa_key(rsa)
{
}

cxy::math::big_integer ossl_rsa_private_key::private_exponent() const {
    return bn2bi(RSA_get0_d(_rsa.get()));
}

//
// ossl_rsa_private_crt_key
//

ossl_rsa_private_crt_key::ossl_rsa_private_crt_key(RSA* rsa) :
ossl_rsa_key(rsa)
{
}

cxy::math::big_integer ossl_rsa_private_crt_key::private_exponent() const {
    return ossl_rsa_private_key::private_exponent();
}

cxy::math::big_integer ossl_rsa_private_crt_key::crt_coefficient() const {
    return bn2bi(RSA_get0_iqmp(_rsa.get()));
}

cxy::math::big_integer ossl_rsa_private_crt_key::prime_exponent_p() const {
    return bn2bi(RSA_get0_dmp1(_rsa.get()));
}

cxy::math::big_integer ossl_rsa_private_crt_key::prime_exponent_q() const {
    return bn2bi(RSA_get0_dmq1(_rsa.get()));
}

cxy::math::big_integer ossl_rsa_private_crt_key::prime_p() const {
    return bn2bi(RSA_get0_p(_rsa.get()));
}

cxy::math::big_integer ossl_rsa_private_crt_key::prime_q() const {
    return bn2bi(RSA_get0_q(_rsa.get()));
}

cxy::math::big_integer ossl_rsa_private_crt_key::public_exponent() const {
    return bn2bi(RSA_get0_e(_rsa.get()));
}

//
// ossl_rsa_multiprime_private_crt_key
//

ossl_rsa_multiprime_private_crt_key::ossl_rsa_multiprime_private_crt_key(RSA* rsa) :
ossl_rsa_key(rsa)
{
}

cxy::math::big_integer ossl_rsa_multiprime_private_crt_key::private_exponent() const {
    return ossl_rsa_private_crt_key::private_exponent();
}

cxy::math::big_integer ossl_rsa_multiprime_private_crt_key::crt_coefficient() const {
    return ossl_rsa_private_crt_key::crt_coefficient();
}

cxy::math::big_integer ossl_rsa_multiprime_private_crt_key::prime_exponent_p() const {
    return ossl_rsa_private_crt_key::prime_exponent_p();
}

cxy::math::big_integer ossl_rsa_multiprime_private_crt_key::prime_exponent_q() const {
    return ossl_rsa_private_crt_key::prime_exponent_q();
}

cxy::math::big_integer ossl_rsa_multiprime_private_crt_key::prime_p() const {
    return ossl_rsa_private_crt_key::prime_p();
}

cxy::math::big_integer ossl_rsa_multiprime_private_crt_key::prime_q() const {
    return ossl_rsa_private_crt_key::prime_q();
}

cxy::math::big_integer ossl_rsa_multiprime_private_crt_key::public_exponent() const {
    return ossl_rsa_private_crt_key::public_exponent();
}

std::vector<cxy::math::big_integer> ossl_rsa_multiprime_private_crt_key::other_prime_info() const {
    // TODO
    throw key_exception("Not implemnted yet");
}



std::shared_ptr<ossl_rsa_private_key> make_rsa_private_key(RSA* rsa) {
    if(rsa!=nullptr) {
        if (RSA_get_version(rsa)==RSA_ASN1_VERSION_MULTI) {
            return std::dynamic_pointer_cast<ossl_rsa_private_key>(std::make_shared<ossl_rsa_multiprime_private_crt_key>(rsa));
        } else if(RSA_get0_p(rsa)  != nullptr && RSA_get0_dmp1(rsa) != nullptr
                && RSA_get0_q(rsa) != nullptr && RSA_get0_dmq1(rsa) != nullptr
                && RSA_get0_iqmp(rsa) != nullptr ) {
            return std::dynamic_pointer_cast<ossl_rsa_private_key>(std::make_shared<ossl_rsa_private_crt_key>(rsa));
        } else {
            return std::dynamic_pointer_cast<ossl_rsa_private_key>(std::make_shared<ossl_rsa_private_key>(rsa));
        }
    } else {
        return nullptr;
    }
}

//
// ossl_rsa_key_pair
//

ossl_rsa_key_pair::ossl_rsa_key_pair(RSA* rsa):
_rsa(make_rsa(rsa))
{}

std::shared_ptr<cxy::security::rsa_public_key> ossl_rsa_key_pair::rsa_public_key() const {
    if(!_pub) {
        _pub = std::make_shared<ossl_rsa_public_key>(RSAPublicKey_dup(_rsa.get()));
    }
    return _pub;
}

std::shared_ptr<cxy::security::rsa_private_key> ossl_rsa_key_pair::rsa_private_key() const {
    if(!_priv) {
        _priv = make_rsa_private_key(RSAPrivateKey_dup(_rsa.get()));
    }
    return _priv;
}

//
// ossl_rsa_key_pair_generator
//

rsa_key_pair_generator& ossl_rsa_key_pair_generator::key_size(size_t key_size) {
    _key_size = key_size;
    return *this;
}

rsa_key_pair_generator& ossl_rsa_key_pair_generator::public_exponent(const cxy::math::big_integer& pub) {
    _pub = pub;
    return *this;
}

size_t ossl_rsa_key_pair_generator::key_size() const {
    return _key_size;
}

cxy::math::big_integer ossl_rsa_key_pair_generator::public_exponent() const {
    return _pub;
}

std::shared_ptr<key_pair> ossl_rsa_key_pair_generator::generate() {
    RSA* rsa = RSA_new();

    // TODO generate multiprime keys

    if(RSA_generate_key_ex(rsa, _key_size, bi2bn(_pub), nullptr)!=0) {
        return std::dynamic_pointer_cast<key_pair>(std::make_shared<ossl_rsa_key_pair>(rsa));
    } else {
        throw std::runtime_error("Error while genrating RSA key");
    }
}




}}} // namespace cxy::security::openssl
