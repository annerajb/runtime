// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace System.Security.Cryptography
{
    [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
    public struct EDDsaParameters
    {
        public System.Security.Cryptography.EDCurve Curve;
        public byte[]? PublicKey;
        public byte[]? PrivateKey;
    }
}
