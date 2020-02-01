/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/key.hpp
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

#ifndef _SECURITY_KEY_HPP_
#define _SECURITY_KEY_HPP_

#include <memory>
#include <vector>
#include <initializer_list>


namespace cxy
{
namespace security
{

/**
 * Base interface for all cryptographic keys.
 */
class key
{
public:
//    key() = default;
//    key(key&&) = default;
//    key(const key&) = default;
//    virtual ~key() = delete;
    virtual ~key() = default;

    /**
     * Return the algorithm of
     */
//    virtual std::string algorithm()const = 0;
};

/**
 * Base interface for all public keys.
 */
class public_key : public virtual key
{
public:
//    virtual ~public_key() = delete;
};

/**
 * Base interface for all private keys.
 */
class private_key : public virtual key
{
public:
//    virtual ~private_key() = delete;
};

/**
 * Base interface for all secret keys.
 */
class secret_key : public virtual key
{
public:
//    secret_key() = default;
//    virtual ~secret_key() = delete;
    /** Size of the key in bytes. */
    virtual size_t size() const =0;
    /** Retrieve the raw value content of the key. */
    virtual std::vector<uint8_t/*std::byte*/> value()const=0;
};



class raw_secret_key : public secret_key
{
protected:
    std::vector<uint8_t/*std::byte*/> _value;

public:
    raw_secret_key() = default;
    raw_secret_key(std::initializer_list<uint8_t/*std::byte*/> init):
        _value(init) {}

    template<typename ... Args>
    raw_secret_key(Args&& ... args):_value(args...) {}

    virtual ~raw_secret_key() = default;

    virtual size_t size() const {return _value.size(); }

    virtual std::vector<uint8_t/*std::byte*/> value()const { return _value;}
    std::vector<uint8_t/*std::byte*/>& value() { return _value;}

};


}} // namespace cxy::security
#endif // _SECURITY_KEY_HPP_
