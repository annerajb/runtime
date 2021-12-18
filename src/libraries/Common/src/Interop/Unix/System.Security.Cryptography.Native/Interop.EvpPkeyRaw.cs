// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_EvpPkeyCreateRawPrivate")]
        internal static extern SafeEvpPKeyHandle EvpPkeyCreateRawPrivate(int type,IntPtr pkey,e,const byte[] key, int len);

        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_EvpPkeyCreateRawPublic")]
        internal static extern SafeEvpPKeyHandle EvpPkeyCreateRawPublic(int type,IntPtr pkey,e,const byte[] key, int len);
        
        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_EvpPkeyGetRawPrivateKey")]
        int32_t CryptoNative_EvpPkeyGetRawPrivateKey(IntPtr pkey, byte[]? priv,out int len);
        
        [DllImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_EvpPkeyGetRawPublicKey")]
        int32_t CryptoNative_EvpPkeyGetRawPublicKey(IntPtr pkey, byte[]? pub,out int len);
    }
}
