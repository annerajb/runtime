// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Internal.Cryptography;
using Internal.Cryptography.Pal;

namespace System.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Provides extension methods for retrieving <see cref="EDDSA" /> implementations for the
    /// public and private keys of a <see cref="X509Certificate2" />.
    /// </summary>
    public static class EDDSACertificateExtensions
    {
        /// <summary>
        /// Gets the <see cref="EDDSA" /> public key from the certificate or null if the certificate does not have an RSA public key.
        /// </summary>
        public static EDDSA? GetEdDsaPublicKey(this X509Certificate2 certificate)
        {
            return certificate.GetPublicKey<EDDSA>();
        }

        /// <summary>
        /// Gets the <see cref="EDDSA" /> private key from the certificate or null if the certificate does not have an RSA private key.
        /// </summary>
        public static EDDSA? GetEdDsaPrivateKey(this X509Certificate2 certificate)
        {
            return certificate.GetPrivateKey<EDDSA>();
        }

        public static X509Certificate2 CopyWithPrivateKey(this X509Certificate2 certificate, EDDSA privateKey)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (certificate.HasPrivateKey)
                throw new InvalidOperationException(SR.Cryptography_Cert_AlreadyHasPrivateKey);

            using (EDDSA? publicKey = GetEdDsaPublicKey(certificate))
            {
                if (publicKey == null)
                    throw new ArgumentException(SR.Cryptography_PrivateKey_WrongAlgorithm);

                byte[] currentParameters = publicKey.ExportPkcs8PrivateKey();
                byte[] newParameters = privateKey.ExportPkcs8PrivateKey();

                if (!currentParameters.ContentsEqual(newParameters))
                {
                    throw new ArgumentException(SR.Cryptography_PrivateKey_DoesNotMatch, nameof(privateKey));
                }
            }

            ICertificatePal pal = certificate.Pal.CopyWithPrivateKey(privateKey);
            return new X509Certificate2(pal);
        }
    }
}
