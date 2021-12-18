// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_evp_raw.h"

EVP_PKEY* CryptoNative_EvpPkeyCreateRawPrivate(int type, ENGINE *e, const uint8_t* key, size_t keylen)
{
    return EVP_PKEY_new_raw_private_key(type,e,key,keylen);
}

EVP_PKEY* CryptoNative_EvpPkeyCreateRawPublic(int type, ENGINE *e, const uint8_t* key, size_t keylen)
{
    return EVP_PKEY_new_raw_public_key(type,e,key,keylen);
}

int32_t CryptoNative_EvpPkeyGetRawPrivateKey(const EVP_PKEY *pkey, uint8_t* priv, size_t* len)
{
    return EVP_PKEY_get_raw_private_key(pkey,priv,len);
}

int32_t CryptoNative_EvpPkeyGetRawPublicKey(const EVP_PKEY *pkey, uint8_t* pub, size_t* len)
{
    return EVP_PKEY_get_raw_public_key(pkey,pub,len);
}
