// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_types.h"
#include "pal_compiler.h"
#include "opensslshim.h"

/*
Shims the EVP_PKEY_new_raw_private_key method.

Returns the new EVP_PKEY instance.
*/
PALEXPORT EVP_PKEY* CryptoNative_EvpPkeyCreateRawPrivate(int type, ENGINE *e, const uint8_t* key, size_t keylen);

/*
Shims the EVP_PKEY_new_raw_public_key method.

Returns the new EVP_PKEY instance.
*/
PALEXPORT EVP_PKEY* CryptoNative_EvpPkeyCreateRawPublic(int type, ENGINE *e, const uint8_t* key, size_t keylen);

/*
Shims the EVP_PKEY_new_raw_public_key method.

Returns the new EVP_PKEY instance.
*/
PALEXPORT int32_t CryptoNative_EvpPkeyGetRawPrivateKey(const EVP_PKEY *pkey, uint8_t* priv, size_t* len);

/*
Shims the EVP_PKEY_new_raw_public_key method.

Returns the new EVP_PKEY instance.
*/
PALEXPORT int32_t CryptoNative_EvpPkeyGetRawPublicKey(const EVP_PKEY *pkey, uint8_t* pub, size_t* len);
