// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_evp_pkey_eddsa.h"
#include "pal_utilities.h"
#include <assert.h>

//todo: this exist on pal_evp.c maybe remove from there or add to shared header or not use it?
#define SUCCESS 1

EVP_PKEY* CryptoNative_EvpPKeyCreateEd25519(EVP_PKEY* currentKey)
{
    assert(currentKey != NULL);
    //TODO define, inquire from library by passing null priv_key buffer and reading return?
    unsigned char privKey[32] = {0};//todo 57 for 448
    size_t privKeyLen = 0;
    int ret = EVP_PKEY_get_raw_private_key(currentKey,privKey,&privKeyLen);
    if (ret != SUCCESS)
    {
        //passed in key does not have a private key
        return NULL;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,privKey,privKeyLen);
    if (pkey == NULL)
    {
        return NULL;
    }

    return pkey;
}

EVP_PKEY* CryptoNative_Ed25519GenerateKey()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

    if (ctx == NULL)
    {
        return NULL;
    }

    EVP_PKEY* pkey = NULL;
    EVP_PKEY* ret = NULL;

    if (EVP_PKEY_keygen_init(ctx) == SUCCESS && EVP_PKEY_keygen(ctx, &pkey) == SUCCESS)
    {
        ret = pkey;
        pkey = NULL;
    }
    //this feels wonky this might be to make sure that we return null pkey in case of failure from evp_pkey_keygen and not any random memory it put in the pkey pointer we gave it.
    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }

    EVP_PKEY_CTX_free(ctx);
    return ret;
}
