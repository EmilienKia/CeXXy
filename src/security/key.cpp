/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/key.cpp
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

#include "key.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <exception>
#include <functional>
#include <map>

#include "openssl.hpp"

namespace cxy
{
namespace security
{

namespace openssl
{

typedef std::shared_ptr<RSA> RSA_sptr;

inline RSA_sptr make_rsa(RSA* rsa) {
    return RSA_sptr(rsa, RSA_free);
}

class ossl_rsa_key : public virtual rsa_key
{
protected:
    RSA_sptr _rsa;

    ossl_rsa_key() = default;

public:
    ossl_rsa_key(RSA* rsa) : _rsa(make_rsa(rsa)) {}

    virtual cxy::math::big_integer modulus() const override {
        return bn2bi(RSA_get0_n(_rsa.get()));
    }
};


class ossl_rsa_public_key : public virtual ossl_rsa_key, public virtual rsa_public_key
{
public:
    ossl_rsa_public_key(RSA* rsa) : ossl_rsa_key(rsa) {}

    virtual cxy::math::big_integer public_exponent() const override {
        return bn2bi(RSA_get0_e(_rsa.get()));
    }
};

class ossl_rsa_private_key : public virtual ossl_rsa_key, public virtual rsa_private_key
{
protected:
    ossl_rsa_private_key() = default;
public:
    ossl_rsa_private_key(RSA* rsa) : ossl_rsa_key(rsa) {}

    virtual cxy::math::big_integer private_exponent() const override {
        return bn2bi(RSA_get0_d(_rsa.get()));
    }
};

class ossl_rsa_private_crt_key : public virtual ossl_rsa_private_key, public virtual rsa_private_crt_key
{
protected:
    ossl_rsa_private_crt_key() = default;
public:
    ossl_rsa_private_crt_key(RSA* rsa) : ossl_rsa_key(rsa) { }

    virtual cxy::math::big_integer private_exponent() const override {
        return ossl_rsa_private_key::private_exponent();
    }

    virtual cxy::math::big_integer crt_coefficient() const override {
        return bn2bi(RSA_get0_iqmp(_rsa.get()));
    }

    virtual cxy::math::big_integer prime_exponent_p() const override {
        return bn2bi(RSA_get0_dmp1(_rsa.get()));
    }

    virtual cxy::math::big_integer prime_exponent_q() const override {
        return bn2bi(RSA_get0_dmq1(_rsa.get()));
    }

    virtual cxy::math::big_integer prime_p() const override {
        return bn2bi(RSA_get0_p(_rsa.get()));
    }

    virtual cxy::math::big_integer prime_q() const override {
        return bn2bi(RSA_get0_q(_rsa.get()));
    }

    virtual cxy::math::big_integer public_exponent() const override {
        return bn2bi(RSA_get0_e(_rsa.get()));
    }
};

class ossl_rsa_multiprime_private_crt_key : public virtual ossl_rsa_private_crt_key, public virtual rsa_multiprime_private_crt_key
{
public:
    ossl_rsa_multiprime_private_crt_key(RSA* rsa) : ossl_rsa_key(rsa) { }

    virtual cxy::math::big_integer private_exponent() const override {
        return ossl_rsa_private_crt_key::private_exponent();
    }

    virtual cxy::math::big_integer crt_coefficient() const override {
        return ossl_rsa_private_crt_key::crt_coefficient();
    }

    virtual cxy::math::big_integer prime_exponent_p() const override {
        return ossl_rsa_private_crt_key::prime_exponent_p();
    }

    virtual cxy::math::big_integer prime_exponent_q() const override {
        return ossl_rsa_private_crt_key::prime_exponent_q();
    }

    virtual cxy::math::big_integer prime_p() const override {
        return ossl_rsa_private_crt_key::prime_p();
    }

    virtual cxy::math::big_integer prime_q() const override {
        return ossl_rsa_private_crt_key::prime_q();
    }

    virtual cxy::math::big_integer public_exponent() const override {
        return ossl_rsa_private_crt_key::public_exponent();
    }

    virtual std::vector<cxy::math::big_integer> other_prime_info() const override {
        // TODO
    }
};

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

class ossl_rsa_key_pair : public rsa_key_pair
{
    RSA_sptr _rsa;

    mutable std::shared_ptr<ossl_rsa_public_key> _pub;
    mutable std::shared_ptr<ossl_rsa_private_key> _priv;

public:
    ossl_rsa_key_pair(RSA* rsa): _rsa(make_rsa(rsa)) {}

    virtual std::shared_ptr<cxy::security::rsa_public_key> rsa_public_key() const override {
        if(!_pub) {
            _pub = std::make_shared<ossl_rsa_public_key>(RSAPublicKey_dup(_rsa.get()));
        }
        return _pub;
    }

    virtual std::shared_ptr<cxy::security::rsa_private_key> rsa_private_key() const override {
        if(!_priv) {
            _priv = make_rsa_private_key(RSAPrivateKey_dup(_rsa.get()));
        }
        return _priv;
    }
};


class ossl_rsa_key_pair_generator : public rsa_key_pair_generator
{
    size_t _key_size = 2048;
    cxy::math::big_integer _pub = rsa_key_pair_generator::F0;

public:
    ossl_rsa_key_pair_generator() = default;

    virtual rsa_key_pair_generator& key_size(size_t key_size) override {
        _key_size = key_size;
        return *this;
    }

    virtual rsa_key_pair_generator& public_exponent(const cxy::math::big_integer& pub) override {
        _pub = pub;
        return *this;
    }

    virtual size_t key_size() const override {
        return _key_size;
    }

    virtual cxy::math::big_integer public_exponent() const {
        return _pub;
    }

    virtual std::shared_ptr<key_pair> generate() override {
        RSA* rsa = RSA_new();

        // TODO generate multiprime keys

        if(RSA_generate_key_ex(rsa, _key_size, bi2bn(_pub), nullptr)!=0) {
            return std::dynamic_pointer_cast<key_pair>(std::make_shared<ossl_rsa_key_pair>(rsa));
        } else {
            // TODO process error
            return nullptr;
        }
    }
};


} // namespace cxy::security::openssl


const cxy::math::big_integer rsa_key_pair_generator::F0{3ul};

const cxy::math::big_integer rsa_key_pair_generator::F4{65537ul};

std::string rsa_key_pair_generator::algorithm() const {
    return "RSA";
}

std::shared_ptr<rsa_key_pair_generator> rsa_key_pair::generator()
{
    return std::dynamic_pointer_cast<rsa_key_pair_generator>(
        std::make_shared<openssl::ossl_rsa_key_pair_generator>()
    );
}



}} // namespace cxy::security
