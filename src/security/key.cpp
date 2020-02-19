/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * security/key.cpp
 * Copyright (C) 2019-2020 Emilien Kia <emilien.kia+dev@gmail.com>
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

#include "openssl.hpp"


namespace cxy
{
namespace security
{

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
