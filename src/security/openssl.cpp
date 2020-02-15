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


}}} // namespace cxy::security::openssl
