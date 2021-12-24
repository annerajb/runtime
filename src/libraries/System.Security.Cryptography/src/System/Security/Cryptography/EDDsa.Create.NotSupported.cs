// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public partial class EDDsa : AsymmetricAlgorithm
    {
        public static new partial EDDsa Create()
        {
            throw new PlatformNotSupportedException();
        }

        public static partial EDDsa Create(EDDsaParameters parameters)
        {
            throw new PlatformNotSupportedException();
        }
    }
}
