/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/security-pem.cpp
 * Copyright (C) 2020 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include "security/openssl.hpp"

#include <cstring>

    static const char* public_key_pem = R"PEM(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtWU0w3aH93h7znGFjdXB
mOYLdsC0H14WjmQpidU3qJ/nE5VpnKFub5tSCemgv7AX/4oC+Knbcsrn0+dxyc5Q
0u1PdETFordw3F+IbPA8+02GY2xxODKufOoXeI8LtUb8ypytf4Hnx15ZW5sZlOJh
6hJ7W03/LnoIO0Ybd/DCF4ksZqylocqdbM/g2OFuDqFrNhwUsPoA4LEMlc16BNeD
N5MMMRa73QS4K7knMq9e2JSBiEqjXZpGu4DNSg8GJtj4OzNvDU+4+mNaF0u/F9u0
6Xf1LG/yhzB9CMPHngqR17ujy3gE3jCLlrvjVVNomtLlb/tps87eGlh89/v8PJwK
NwIDAQAB
-----END PUBLIC KEY-----
)PEM";


    static const char* private_key_pem = R"PEM(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,B55517526E647AA4

omSrmPOHxQXBcOzONYvtLUYYLEm8TeN6NhZfKz11YnnxNKtcMaItF8m7NMXeO+Ae
YfdXdhUiWh3F09/y26rO94lOugSW8mQieP06gsMhBuailnBsmMh/zmzyfNL/Cht7
ky3GuYP/tQSjipEQSgIn6ti/UG1CepzoaRCMgRJ51lBicEgcOSHMbPiSekd968UY
xY6bE3Aer50yrsptFhkVPNL9+QLMivGVzb25CVKIInPTGlh/vAjm9zp9DGsmGJh6
OqmeEAR4awva3UDPR0TCqO4+InyKbWFjV7Bc6b6447gEW1VBfdAElSzHZbUg2h3O
Wtf3EKKQlcdtxmi6FE2QGcGsMOhux088Zcc64sK39aioCT0oWNU0Btufbf9Kb+z9
zkj/omeqoRM2SLYCI4Xtjpjr2mnz0tl8cqaLfceFwo2PB/qNnf0Azz+FuXO4SxFZ
TcL1fmRt+ZHqW4Ja3eeiYbDxx8hQXGXZ25ouY7vE4xmqkNLhyws8CMfX31psGnbn
6tFW+Ie7KKy5BeKujemX4CUfOB4yG3NMV2Fg1r9m0D+ZCBnXaWayP4X+XfJf1tI6
mtpqaJkX5fS52iIso+KnALbPFnoqfQmNDiL96nOq9/FRrIZBAC4muN91V4ga5udA
nrKs4JIBaEsdg6KuUhs2mNldSWc0IwPEANe+NiQ6OEt+N+r/wa8bPE+Lvr2LNrPD
Y8Ln5neACduYu/NjaDjHjeFTrt+OtIkJomV1gdzoTSj8/b8L6OmEoVoYjR7Mb2u9
9GM4E6SQqIksQBE/YSjIq0/c9TNkxaNMcLLwKOeWdbG+1gvzwGmiawdl4z9WC9ii
MQ83ddgZPUBknjyQ+7MrobkTDU7ObqLWIoMXB5YQV6uoBSlxc0at/JbdvLcyHXEm
uA0E+hCDqrT2U6mibFPlsdj7Hd8V5CoyjmVvX1fn9pP+zrmL12o03CvoV0LpOaHR
y1UvMMuynTfi+q2zz1ybScg9BZim/7ulDWh9P979Ax3lMqOPEvx741svrFy2M5/b
+4IEGXqMlLMsiWSpBnkbMUM14iojzF2obNbD5CkNsZEkzk1QyCXgdXWB9hgTHrIi
nTF37R0DgUuZj8dSe+jJfzbsXwIX8n0jl9N5j/a/qYWAkrZxvSff0lHpHBYD03LZ
wMD0dQ8Gy4zIDBpQDK/S0F+xOWwg/WhrJAvBN81XwO3yuia8LE7JRZU76SbPxF0u
tqlPTqCA8vaWxlsEJdgUVhphjxsRlN0dbKQCOtuPpKWFP/jfY/Iiiu8gFlMe6gWk
py3nmy0/6IYG/WBRWze0jHOTj1fTQuvSo1YMg1ywZp3lxJ7PoAglSsWQtMwQMb5i
Bzga6GwltVlyOp3Wlc/sXUS0fz2R7tvk/tg3pRUT5u0M7VWqV6nyJT3CRdpp7gES
Rox8GFTqIyJoph+vRqI0GlpogGChjHxppFKmT03fFNTxh1oykMlmLssurfYTluuP
00TzbcCx3ywyKxYSPl01/bcOmIob2oFKFJqHUDUMuNEaW2eUrqbrdK33ffoKbHkI
8djTPNFLWdcADE6u6s2XpE1SDkgqf23IpT+e9SASSJNZcQbjYzJv+A==
-----END RSA PRIVATE KEY-----
)PEM";


TEST_CASE( "PEM reader from mem", "[PEM]" ) {
    using namespace cxy::security;

    auto pubread = new openssl::ossl_FILE_pem_reader(public_key_pem, std::strlen(public_key_pem));
    REQUIRE( pubread != nullptr );

    auto pubkey = pubread->public_key();
    REQUIRE( pubkey.get() != nullptr );


    auto privread = new openssl::ossl_FILE_pem_reader(private_key_pem, std::strlen(private_key_pem));
    REQUIRE( private_key_pem != nullptr );

    auto privkey = privread->private_key("tititoto");
    REQUIRE( privkey.get() != nullptr );

}
