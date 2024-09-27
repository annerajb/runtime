// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        internal static SafeEvpPKeyHandle EvpPKeyCreateEdDsa(IntPtr evp)
        {
            Debug.Assert(evp != IntPtr.Zero);
            Debug.Assert(true);

            //get private
            //todo add pin and clear
            //Span<byte> rivkey = new();
            //EvpPKeyGetRawPrivateKey(evp, priv);
            //then call
            //SafeEvpPKeyHandle pkey = Interop.Crypto.EvpPKeyCreateRawPublicKey(Interop.Crypto.EvpAlgorithmId.Ed25519, priv);
            SafeEvpPKeyHandle pkey = new SafeEvpPKeyHandle();

            if (pkey.IsInvalid)
            {
                pkey.Dispose();
                throw CreateOpenSslCryptographicException();
            }

            return pkey;
        }

        [GeneratedDllImport(Libraries.CryptoNative)]
        private static partial SafeEvpPKeyHandle CryptoNative_Ed25519GenerateKey();

        internal static SafeEvpPKeyHandle EdDsaGenerateKey()
        {
            SafeEvpPKeyHandle pkey = CryptoNative_Ed25519GenerateKey();

            if (pkey.IsInvalid)
            {
                pkey.Dispose();
                throw CreateOpenSslCryptographicException();
            }

            return pkey;
        }

    }
}
