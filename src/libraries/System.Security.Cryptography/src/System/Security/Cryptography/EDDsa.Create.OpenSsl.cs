// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    public partial class EDDsa : AsymmetricAlgorithm
    {
        /// <summary>
        /// Creates an instance of the platform specific implementation of the cref="EDDsa" algorithm.
        /// </summary>
        /// <param name="parameters">
        /// The <see cref="EDDsaParameters"/> representing the elliptic curve parameters.
        /// </param>
        public static partial EDDsa Create(EDDsaParameters parameters)
        {
            EDDsa ed = new EDDsaImplementation.EDDsaOpenSsl();
            ed.ImportParameters(parameters);
            return ed;
        }
    }
}
