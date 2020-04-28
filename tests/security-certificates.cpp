/* -*- Mode: CPP; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * tests/security-certificates.cpp
 * Copyright (C) 2020 Emilien Kia <emilien.kia+dev@gmail.com>
 */

#include "catch.hpp"

#include "security/openssl.hpp"

#include <iostream>
#include <cstring>


static const std::string github_certificate { R"PEM(
-----BEGIN CERTIFICATE-----
MIIHQjCCBiqgAwIBAgIQCgYwQn9bvO1pVzllk7ZFHzANBgkqhkiG9w0BAQsFADB1
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVk
IFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTE4MDUwODAwMDAwMFoXDTIwMDYwMzEy
MDAwMFowgccxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYB
BAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQITCERlbGF3YXJlMRAwDgYDVQQF
Ewc1MTU3NTUwMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQG
A1UEBxMNU2FuIEZyYW5jaXNjbzEVMBMGA1UEChMMR2l0SHViLCBJbmMuMRMwEQYD
VQQDEwpnaXRodWIuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
xjyq8jyXDDrBTyitcnB90865tWBzpHSbindG/XqYQkzFMBlXmqkzC+FdTRBYyneZ
w5Pz+XWQvL+74JW6LsWNc2EF0xCEqLOJuC9zjPAqbr7uroNLghGxYf13YdqbG5oj
/4x+ogEG3dF/U5YIwVr658DKyESMV6eoYV9mDVfTuJastkqcwero+5ZAKfYVMLUE
sMwFtoTDJFmVf6JlkOWwsxp1WcQ/MRQK1cyqOoUFUgYylgdh3yeCDPeF22Ax8AlQ
xbcaI+GwfQL1FB7Jy+h+KjME9lE/UpgV6Qt2R1xNSmvFCBWu+NFX6epwFP/JRbkM
fLz0beYFUvmMgLtwVpEPSwIDAQABo4IDeTCCA3UwHwYDVR0jBBgwFoAUPdNQpdag
re7zSmAKZdMh1Pj41g8wHQYDVR0OBBYEFMnCU2FmnV+rJfQmzQ84mqhJ6kipMCUG
A1UdEQQeMByCCmdpdGh1Yi5jb22CDnd3dy5naXRodWIuY29tMA4GA1UdDwEB/wQE
AwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYDVR0fBG4wbDA0
oDKgMIYuaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItZXYtc2VydmVyLWcy
LmNybDA0oDKgMIYuaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTItZXYtc2Vy
dmVyLWcyLmNybDBLBgNVHSAERDBCMDcGCWCGSAGG/WwCATAqMCgGCCsGAQUFBwIB
FhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAcGBWeBDAEBMIGIBggrBgEF
BQcBAQR8MHowJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBS
BggrBgEFBQcwAoZGaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
U0hBMkV4dGVuZGVkVmFsaWRhdGlvblNlcnZlckNBLmNydDAMBgNVHRMBAf8EAjAA
MIIBfgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdgCkuQmQtBhYFIe7E6LMZ3AKPDWY
BPkb37jjd80OyA3cEAAAAWNBYm0KAAAEAwBHMEUCIQDRZp38cTWsWH2GdBpe/uPT
Wnsu/m4BEC2+dIcvSykZYgIgCP5gGv6yzaazxBK2NwGdmmyuEFNSg2pARbMJlUFg
U5UAdgBWFAaaL9fC7NP14b1Esj7HRna5vJkRXMDvlJhV1onQ3QAAAWNBYm0tAAAE
AwBHMEUCIQCi7omUvYLm0b2LobtEeRAYnlIo7n6JxbYdrtYdmPUWJQIgVgw1AZ51
vK9ENinBg22FPxb82TvNDO05T17hxXRC2IYAdgC72d+8H4pxtZOUI5eqkntHOFeV
CqtS6BqQlmQ2jh7RhQAAAWNBYm3fAAAEAwBHMEUCIQChzdTKUU2N+XcqcK0OJYrN
8EYynloVxho4yPk6Dq3EPgIgdNH5u8rC3UcslQV4B9o0a0w204omDREGKTVuEpxG
eOQwDQYJKoZIhvcNAQELBQADggEBAHAPWpanWOW/ip2oJ5grAH8mqQfaunuCVE+v
ac+88lkDK/LVdFgl2B6kIHZiYClzKtfczG93hWvKbST4NRNHP9LiaQqdNC17e5vN
HnXVUGw+yxyjMLGqkgepOnZ2Rb14kcTOGp4i5AuJuuaMwXmCo7jUwPwfLe1NUlVB
Kqg6LK0Hcq4K0sZnxE8HFxiZ92WpV2AVWjRMEc/2z2shNoDvxvFUYyY1Oe67xINk
myQKc+ygSBZzyLnXSFVWmHr3u5dcaaQGGAR42v6Ydr4iL38Hd4dOiBma+FXsXBIq
WUjbST4VXmdaol7uzFMojA4zkxQDZAvF5XgJlAFadfySna/teik=
-----END CERTIFICATE-----
)PEM"};


TEST_CASE( "Read X509 certificate from PEM", "[PEM][X509]" ) {
    using namespace cxy::security;

    openssl::ossl_string_pem_reader reader(github_certificate);

    auto cert = reader.x509_certificate();
    REQUIRE( cert != nullptr );

    std::string subject_name = cert->subject().name();
    REQUIRE( std::string::npos != subject_name.find("C=US") ); // TODO Optimistic test, to be refine
    REQUIRE( std::string::npos != subject_name.find("ST=California") ); // TODO Optimistic test, to be refine
    REQUIRE( std::string::npos != subject_name.find("L=San Francisco") ); // TODO Optimistic test, to be refine
    REQUIRE( std::string::npos != subject_name.find("O=GitHub\\, Inc.") ); // TODO Optimistic test, to be refine
    REQUIRE( std::string::npos != subject_name.find("CN=github.com") ); // TODO Optimistic test, to be refine

    std::string issuer_name = cert->issuer().name();
    REQUIRE( std::string::npos != issuer_name.find("C=US") ); // TODO Optimistic test, to be refine
    REQUIRE( std::string::npos != issuer_name.find("O=DigiCert Inc") ); // TODO Optimistic test, to be refine
    REQUIRE( std::string::npos != issuer_name.find("OU=www.digicert.com") ); // TODO Optimistic test, to be refine
    REQUIRE( std::string::npos != issuer_name.find("CN=DigiCert SHA2 Extended Validation Server CA") ); // TODO Optimistic test, to be refine

    cxy::math::big_integer serial("0A0630427F5BBCED6957396593B6451F", 16);
    REQUIRE( cert->serial_number() == serial );

    auto pubkey = cert->public_key();
    REQUIRE( pubkey != nullptr );

    auto rsapubkey = std::dynamic_pointer_cast<rsa_public_key>(pubkey);
    REQUIRE( rsapubkey != nullptr );
    REQUIRE( rsapubkey->modulus_size() == 2048 );
    REQUIRE( rsapubkey->public_exponent() == 65537l );
    cxy::math::big_integer modulus("C63CAAF23C970C3AC14F28AD72707DD3"
                                   "CEB9B56073A4749B8A7746FD7A98424C"
                                   "C53019579AA9330BE15D4D1058CA7799"
                                   "C393F3F97590BCBFBBE095BA2EC58D73"
                                   "6105D31084A8B389B82F738CF02A6EBE"
                                   "EEAE834B8211B161FD7761DA9B1B9A23"
                                   "FF8C7EA20106DDD17F539608C15AFAE7"
                                   "C0CAC8448C57A7A8615F660D57D3B896"
                                   "ACB64A9CC1EAE8FB964029F61530B504"
                                   "B0CC05B684C32459957FA26590E5B0B3"
                                   "1A7559C43F31140AD5CCAA3A85055206"
                                   "32960761DF27820CF785DB6031F00950"
                                   "C5B71A23E1B07D02F5141EC9CBE87E2A"
                                   "3304F6513F529815E90B76475C4D4A6B"
                                   "C50815AEF8D157E9EA7014FFC945B90C"
                                   "7CBCF46DE60552F98C80BB7056910F4B", 16);
    REQUIRE( rsapubkey->modulus() == modulus );
}


