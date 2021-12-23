// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    public partial class EDDSA : AsymmetricAlgorithm
    {
        public static new partial EDDSA Create()
        {
            throw new PlatformNotSupportedException();
        }
    }
}
