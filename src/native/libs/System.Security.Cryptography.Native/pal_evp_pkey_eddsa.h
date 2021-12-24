// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "opensslshim.h"
#include "pal_compiler.h"
#include "pal_types.h"

/*
Creates an Ed25519 key of the requested size.
*/
PALEXPORT EVP_PKEY* CryptoNative_Ed25519GenerateKey(void);
