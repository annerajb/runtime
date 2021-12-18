// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using Internal.Cryptography;
using Internal.Cryptography.Pal;

namespace System.Security.Cryptography.X509Certificates.System.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Provides extension methods for retrieving <see cref="EdDsa" /> implementations for the
    /// public and private keys of a <see cref="X509Certificate2" />.
    /// </summary>
    public static class EdDsaCertificateExtensions
    {
        /// <summary>
        /// Gets the <see cref="EdDsa" /> public key from the certificate or null if the certificate does not have an EdDsa public key.
        /// </summary>
        public static EdDsa? GetEdDsaPublicKey(this X509Certificate2 certificate)
        {
            return certificate.GetPublicKey<EdDsa>(cert => HasEdDsaKeyUsage(cert));
        }

        /// <summary>
        /// Gets the <see cref="EdDsa" /> private key from the certificate or null if the certificate does not have an EdDsa private key.
        /// </summary>
        public static EdDsa? GetEdDsaPrivateKey(this X509Certificate2 certificate)
        {
            return certificate.GetPrivateKey<EdDsa>(cert => HasEdDsaKeyUsage(cert));
        }

        public static X509Certificate2 CopyWithPrivateKey(this X509Certificate2 certificate, EdDsa privateKey)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (certificate.HasPrivateKey)
                throw new InvalidOperationException(SR.Cryptography_Cert_AlreadyHasPrivateKey);

            using (EdDsa? publicKey = GetEdDsaPublicKey(certificate))
            {
                if (publicKey == null)
                    throw new ArgumentException(SR.Cryptography_PrivateKey_WrongAlgorithm);

                if (!IsSameKey(publicKey, privateKey))
                {
                    throw new ArgumentException(SR.Cryptography_PrivateKey_DoesNotMatch, nameof(privateKey));
                }
            }

            ICertificatePal pal = certificate.Pal.CopyWithPrivateKey(privateKey);
            return new X509Certificate2(pal);
        }

        private static bool HasEdDsaKeyUsage(X509Certificate2 certificate)
        {
            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension.Oid!.Value == Oids.KeyUsage)
                {
                    X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;

                    if ((ext.KeyUsages & X509KeyUsageFlags.KeyAgreement) == 0)
                    {
                        // If this does not have KeyAgreement flag present, it cannot be ECDH
                        // or ECMQV key as KeyAgreement is mandatory flag for ECDH or ECMQV (RFC 5480 Section 3).
                        //
                        // In that case, at this point, it is safe to assume it is EdDsa
                        return true;
                    }

                    // Even if KeyAgreement was specified, if any of the signature uses was
                    // specified then EdDsa is a valid usage.
                    const X509KeyUsageFlags EdDsaFlags =
                        X509KeyUsageFlags.DigitalSignature |
                        X509KeyUsageFlags.NonRepudiation |
                        X509KeyUsageFlags.KeyCertSign |
                        X509KeyUsageFlags.CrlSign;

                    return ((ext.KeyUsages & EdDsaFlags) != 0);
                }
            }

            // If the key usage extension is not present in the certificate it is
            // considered valid for all usages, so we can use it for EdDsa.
            return true;
        }

        private static bool IsSameKey(EdDsa a, EdDsa b)
        {
            ECParameters aParameters = a.ExportParameters(false);
            ECParameters bParameters = b.ExportParameters(false);

            if (aParameters.Curve.CurveType != bParameters.Curve.CurveType)
                return false;

            if (!aParameters.Q.X!.ContentsEqual(bParameters.Q.X!) ||
                !aParameters.Q.Y!.ContentsEqual(bParameters.Q.Y!))
            {
                return false;
            }

            ECCurve aCurve = aParameters.Curve;
            ECCurve bCurve = bParameters.Curve;

            if (aCurve.IsNamed)
            {
                // On Windows we care about FriendlyName, on Unix we care about Value
                return (aCurve.Oid.Value == bCurve.Oid.Value && aCurve.Oid.FriendlyName == bCurve.Oid.FriendlyName);
            }

            if (!aCurve.IsExplicit)
            {
                // Implicit curve, always fail.
                return false;
            }

            // Ignore Cofactor (which is derivable from the prime or polynomial and Order)
            // Ignore Seed and Hash (which are entirely optional, and about how A and B were built)
            if (!aCurve.G.X!.ContentsEqual(bCurve.G.X!) ||
                !aCurve.G.Y!.ContentsEqual(bCurve.G.Y!) ||
                !aCurve.Order.ContentsEqual(bCurve.Order) ||
                !aCurve.A.ContentsEqual(bCurve.A) ||
                !aCurve.B.ContentsEqual(bCurve.B))
            {
                return false;
            }

            if (aCurve.IsPrime)
            {
                return aCurve.Prime.ContentsEqual(bCurve.Prime);
            }

            if (aCurve.IsCharacteristic2)
            {
                return aCurve.Polynomial.ContentsEqual(bCurve.Polynomial);
            }

            Debug.Fail($"Missing match criteria for curve type {aCurve.CurveType}");
            return false;
        }
    }
}
