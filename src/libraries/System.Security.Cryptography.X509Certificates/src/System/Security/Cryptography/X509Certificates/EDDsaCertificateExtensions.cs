// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Internal.Cryptography;
using Internal.Cryptography.Pal;

namespace System.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Provides extension methods for retrieving <see cref="EDDsa" /> implementations for the
    /// public and private keys of a <see cref="X509Certificate2" />.
    /// </summary>
    public static class EDDsaCertificateExtensions
    {
        /// <summary>
        /// Gets the <see cref="EDDsa" /> public key from the certificate or null if the certificate does not have an RSA public key.
        /// </summary>
        public static EDDsa? GetEDDsaPublicKey(this X509Certificate2 certificate)
        {
            return certificate.GetPublicKey<EDDsa>();
        }

        /// <summary>
        /// Gets the <see cref="EDDsa" /> private key from the certificate or null if the certificate does not have an RSA private key.
        /// </summary>
        public static EDDsa? GetEDDsaPrivateKey(this X509Certificate2 certificate)
        {
            return certificate.GetPrivateKey<EDDsa>();
        }

        public static X509Certificate2 CopyWithPrivateKey(this X509Certificate2 certificate, EDDsa privateKey)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (certificate.HasPrivateKey)
                throw new InvalidOperationException(SR.Cryptography_Cert_AlreadyHasPrivateKey);

            using (EDDsa? publicKey = GetEDDsaPublicKey(certificate))
            {
                if (publicKey == null)
                    throw new ArgumentException(SR.Cryptography_PrivateKey_WrongAlgorithm);

                EDDsaParameters currentParameters = publicKey.ExportParameters(false);
                EDDsaParameters newParameters = privateKey.ExportParameters(false);

                if (!currentParameters.Key.ContentsEqual(newParameters.Key))
                {
                    throw new ArgumentException(SR.Cryptography_PrivateKey_DoesNotMatch, nameof(privateKey));
                }
            }

            ICertificatePal pal = certificate.Pal.CopyWithPrivateKey(privateKey);
            return new X509Certificate2(pal);
        }
    }
}
