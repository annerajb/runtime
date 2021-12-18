// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Internal.Cryptography;
using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    [UnsupportedOSPlatform("browser")]
    public abstract partial class EdDsa : AsymmetricAlgorithm
    {
        // secp521r1 maxes out at 139 bytes in the DER format, so 256 should always be enough
        //private const int SignatureStackBufSize = 256;
        // The biggest supported hash algorithm is SHA-2-512, which is only 64 bytes.
        // One power of two bigger should cover most unknown algorithms, too.
        private const int HashBufferStackSize = 128;

        private static readonly string[] s_validOids =
        {
            Oids.Ed25519,
            Oids.Ed448
        };

        protected EdDsa() { }
        public static new EdDsa? Create()
        {
            return CryptoConfig.CreateFromName("EdDsa") as EdDsa;
        }
        public static new EdDsa? Create(string algorithm)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            return CryptoConfig.CreateFromName(algorithm) as EdDsa;
        }
        /// <summary>
        /// When overridden in a derived class, exports the explicit ECParameters for an ECCurve.
        /// </summary>
        /// <param name="includePrivateParameters">true to include private parameters, otherwise, false.</param>
        /// <returns></returns>
        public virtual ECParameters ExportExplicitParameters(bool includePrivateParameters)
        {
            throw new NotSupportedException(SR.NotSupported_SubclassOverride);
        }

        /// <summary>
        /// When overridden in a derived class, imports the specified ECParameters.
        /// </summary>
        /// <param name="parameters">The curve parameters.</param>
        public virtual void ImportParameters(ECParameters parameters)
        {
            throw new NotSupportedException(SR.NotSupported_SubclassOverride);
        }

        /// <summary>
        /// When overridden in a derived class, generates a new public/private keypair for the specified curve.
        /// </summary>
        /// <param name="curve">The curve to use.</param>
        public virtual void GenerateKey(ECCurve curve)
        {
            throw new NotSupportedException(SR.NotSupported_SubclassOverride);
        }


        public override string? KeyExchangeAlgorithm => null;
        public override string SignatureAlgorithm => "EdDsa";

        protected virtual byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            throw new NotSupportedException(SR.NotSupported_SubclassOverride);
        }

        protected virtual byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            throw new NotSupportedException(SR.NotSupported_SubclassOverride);
        }

        // protected virtual bool TryHashData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten)
        // {
        //     // Use ArrayPool.Shared instead of CryptoPool because the array is passed out.
        //     byte[] array = ArrayPool<byte>.Shared.Rent(data.Length);
        //     bool returnArray = false;

        //     try
        //     {
        //         data.CopyTo(array);
        //         byte[] hash = HashData(array, 0, data.Length, hashAlgorithm);
        //         returnArray = true;

        //         if (hash.Length <= destination.Length)
        //         {
        //             new ReadOnlySpan<byte>(hash).CopyTo(destination);
        //             bytesWritten = hash.Length;
        //             return true;
        //         }
        //         else
        //         {
        //             bytesWritten = 0;
        //             return false;
        //         }
        //     }
        //     finally
        //     {
        //         Array.Clear(array, 0, data.Length);

        //         if (returnArray)
        //         {
        //             ArrayPool<byte>.Shared.Return(array);
        //         }
        //     }
        // }

        private ReadOnlySpan<byte> HashSpanToTmp(
            ReadOnlySpan<byte> data,
            HashAlgorithmName hashAlgorithm,
            Span<byte> tmp)
        {
            Debug.Assert(tmp.Length == HashBufferStackSize);

            // if (TryHashData(data, tmp, hashAlgorithm, out int hashSize))
            // {
            //     return tmp.Slice(0, hashSize);
            // }

            // This is not expected, but a poor virtual implementation of TryHashData,
            // or an exotic new algorithm, will hit this fallback.
            return HashSpanToArray(data, hashAlgorithm);
        }

        private byte[] HashSpanToArray(ReadOnlySpan<byte> data, HashAlgorithmName hashAlgorithm)
        {
            // Use ArrayPool.Shared instead of CryptoPool because the array is passed out.
            byte[] array = ArrayPool<byte>.Shared.Rent(data.Length);
            bool returnArray = false;
            try
            {
                data.CopyTo(array);
                byte[] ret = HashData(array, 0, data.Length, hashAlgorithm);
                returnArray = true;
                return ret;
            }
            finally
            {
                Array.Clear(array, 0, data.Length);

                if (returnArray)
                {
                    ArrayPool<byte>.Shared.Return(array);
                }
            }
        }

        public override unsafe bool TryExportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            PbeParameters pbeParameters,
            Span<byte> destination,
            out int bytesWritten)
        {
            if (pbeParameters == null)
                throw new ArgumentNullException(nameof(pbeParameters));

            PasswordBasedEncryption.ValidatePbeParameters(
                pbeParameters,
                ReadOnlySpan<char>.Empty,
                passwordBytes);

            // ECParameters ecParameters = ExportParameters(true);

            // fixed (byte* privPtr = ecParameters.D)
            // {
            //     try
            //     {
            //         AsnWriter pkcs8PrivateKey = EccKeyFormatHelper.WritePkcs8PrivateKey(ecParameters);

            //         AsnWriter writer = KeyFormatHelper.WriteEncryptedPkcs8(
            //             passwordBytes,
            //             pkcs8PrivateKey,
            //             pbeParameters);

            //         return writer.TryEncode(destination, out bytesWritten);
            //     }
            //     finally
            //     {
            //         CryptographicOperations.ZeroMemory(ecParameters.D);
            //     }
            // }
            return false;
        }

        public override unsafe bool TryExportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            PbeParameters pbeParameters,
            Span<byte> destination,
            out int bytesWritten)
        {
            if (pbeParameters == null)
                throw new ArgumentNullException(nameof(pbeParameters));

            PasswordBasedEncryption.ValidatePbeParameters(
                pbeParameters,
                password,
                ReadOnlySpan<byte>.Empty);

            // ECParameters ecParameters = ExportParameters(true);
            return false;
            // fixed (byte* privPtr = ecParameters.D)
            // {
            //     try
            //     {
            //         AsnWriter pkcs8PrivateKey = EccKeyFormatHelper.WritePkcs8PrivateKey(ecParameters);

            //         AsnWriter writer = KeyFormatHelper.WriteEncryptedPkcs8(
            //             password,
            //             pkcs8PrivateKey,
            //             pbeParameters);

            //         return writer.TryEncode(destination, out bytesWritten);
            //     }
            //     finally
            //     {
            //         CryptographicOperations.ZeroMemory(ecParameters.D);
            //     }
            // }
        }

        public override unsafe bool TryExportPkcs8PrivateKey(
            Span<byte> destination,
            out int bytesWritten)
        {
            return false;
            // ECParameters ecParameters = ExportParameters(true);

            // fixed (byte* privPtr = ecParameters.D)
            // {
            //     try
            //     {
            //         AsnWriter writer = EccKeyFormatHelper.WritePkcs8PrivateKey(ecParameters);
            //         return writer.TryEncode(destination, out bytesWritten);
            //     }
            //     finally
            //     {
            //         CryptographicOperations.ZeroMemory(ecParameters.D);
            //     }
            // }
        }

        public override bool TryExportSubjectPublicKeyInfo(
            Span<byte> destination,
            out int bytesWritten)
        {
            // ECParameters ecParameters = ExportParameters(false);

            // AsnWriter writer = EccKeyFormatHelper.WriteSubjectPublicKeyInfo(ecParameters);
            // return writer.TryEncode(destination, out bytesWritten);
            return false;
        }

        public override unsafe void ImportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<byte> passwordBytes,
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            KeyFormatHelper.ReadEncryptedPkcs8<ECParameters>(
                s_validOids,
                source,
                passwordBytes,
                EccKeyFormatHelper.FromECPrivateKey,
                out int localRead,
                out ECParameters ret);

            fixed (byte* privPin = ret.D)
            {
                try
                {
                    ImportParameters(ret);
                    bytesRead = localRead;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ret.D);
                }
            }
        }

        public override unsafe void ImportEncryptedPkcs8PrivateKey(
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            KeyFormatHelper.ReadEncryptedPkcs8<ECParameters>(
                s_validOids,
                source,
                password,
                EccKeyFormatHelper.FromECPrivateKey,
                out int localRead,
                out ECParameters ret);

            fixed (byte* privPin = ret.D)
            {
                try
                {
                    ImportParameters(ret);
                    bytesRead = localRead;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ret.D);
                }
            }
        }

        public override unsafe void ImportPkcs8PrivateKey(
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            KeyFormatHelper.ReadPkcs8<ECParameters>(
                s_validOids,
                source,
                EccKeyFormatHelper.FromECPrivateKey,
                out int localRead,
                out ECParameters key);

            fixed (byte* privPin = key.D)
            {
                try
                {
                    ImportParameters(key);
                    bytesRead = localRead;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key.D);
                }
            }
        }

        public override void ImportSubjectPublicKeyInfo(
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            KeyFormatHelper.ReadSubjectPublicKeyInfo<ECParameters>(
                s_validOids,
                source,
                EccKeyFormatHelper.FromECPublicKey,
                out int localRead,
                out ECParameters key);

            ImportParameters(key);
            bytesRead = localRead;
        }

        public virtual unsafe void ImportECPrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            ECParameters ecParameters = EccKeyFormatHelper.FromECPrivateKey(source, out int localRead);

            fixed (byte* privPin = ecParameters.D)
            {
                try
                {
                    ImportParameters(ecParameters);
                    bytesRead = localRead;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(ecParameters.D);
                }
            }
        }

        public virtual unsafe byte[] ExportECPrivateKey()
        {
            // ECParameters ecParameters = ExportParameters(true);

            // fixed (byte* privPin = ecParameters.D)
            // {
            //     try
            //     {
            //         AsnWriter writer = EccKeyFormatHelper.WriteECPrivateKey(ecParameters);
            //         return writer.Encode();
            //     }
            //     finally
            //     {
            //         CryptographicOperations.ZeroMemory(ecParameters.D);
            //     }
            // }
            return false;
        }

        public virtual unsafe bool TryExportECPrivateKey(Span<byte> destination, out int bytesWritten)
        {
            // ECParameters ecParameters = ExportParameters(true);

            // fixed (byte* privPin = ecParameters.D)
            // {
            //     try
            //     {
            //         AsnWriter writer = EccKeyFormatHelper.WriteECPrivateKey(ecParameters);
            //         return writer.TryEncode(destination, out bytesWritten);
            //     }
            //     finally
            //     {
            //         CryptographicOperations.ZeroMemory(ecParameters.D);
            //     }
            // }
            return false;
        }

        /// <summary>
        ///   Gets the largest size, in bytes, for a signature produced by this key in the indicated format.
        /// </summary>
        /// <param name="signatureFormat">The encoding format for a signature.</param>
        /// <returns>
        ///   The largest size, in bytes, for a signature produced by this key in the indicated format.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="signatureFormat"/> is not a known format.
        /// </exception>
        public int GetMaxSignatureSize(DSASignatureFormat signatureFormat)
        {
            int fieldSizeBits = KeySize;

            if (fieldSizeBits == 0)
            {
                // Coerce the key/key-size into existence
                //ExportParameters(false);

                fieldSizeBits = KeySize;

                // This implementation of ECDsa doesn't set KeySize, we can't
                if (fieldSizeBits == 0)
                {
                    throw new NotSupportedException(SR.Cryptography_InvalidKeySize);
                }
            }

            switch (signatureFormat)
            {
                case DSASignatureFormat.IeeeP1363FixedFieldConcatenation:
                    return AsymmetricAlgorithmHelpers.BitsToBytes(fieldSizeBits) * 2;
                case DSASignatureFormat.Rfc3279DerSequence:
                    return AsymmetricAlgorithmHelpers.GetMaxDerSignatureSize(fieldSizeBits);
                default:
                    throw new ArgumentOutOfRangeException(nameof(signatureFormat));
            }
        }

        /// <summary>
        /// Imports an RFC 7468 PEM-encoded key, replacing the keys for this object.
        /// </summary>
        /// <param name="input">The PEM text of the key to import.</param>
        /// <exception cref="ArgumentException">
        /// <para>
        ///   <paramref name="input"/> does not contain a PEM-encoded key with a recognized label.
        /// </para>
        /// <para>
        ///   -or-
        /// </para>
        /// <para>
        ///   <paramref name="input"/> contains multiple PEM-encoded keys with a recognized label.
        /// </para>
        /// <para>
        ///     -or-
        /// </para>
        /// <para>
        ///   <paramref name="input"/> contains an encrypted PEM-encoded key.
        /// </para>
        /// </exception>
        /// <remarks>
        ///   <para>
        ///   Unsupported or malformed PEM-encoded objects will be ignored. If multiple supported PEM labels
        ///   are found, an exception is raised to prevent importing a key when
        ///   the key is ambiguous.
        ///   </para>
        ///   <para>
        ///   This method supports the following PEM labels:
        ///   <list type="bullet">
        ///     <item><description>PUBLIC KEY</description></item>
        ///     <item><description>PRIVATE KEY</description></item>
        ///   </list>
        ///   </para>
        /// </remarks>
        public override void ImportFromPem(ReadOnlySpan<char> input)
        {
            PemKeyImportHelpers.ImportPem(input, label => {
                if (label.SequenceEqual(PemLabels.Pkcs8PrivateKey))
                {
                    return ImportPkcs8PrivateKey;
                }
                else if (label.SequenceEqual(PemLabels.SpkiPublicKey))
                {
                    return ImportSubjectPublicKeyInfo;
                }
                else
                {
                    return null;
                }
            });
        }

        /// <summary>
        /// Imports an encrypted RFC 7468 PEM-encoded private key, replacing the keys for this object.
        /// </summary>
        /// <param name="input">The PEM text of the encrypted key to import.</param>
        /// <param name="password">
        /// The password to use for decrypting the key material.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <para>
        ///   <paramref name="input"/> does not contain a PEM-encoded key with a recognized label.
        /// </para>
        /// <para>
        ///    -or-
        /// </para>
        /// <para>
        ///   <paramref name="input"/> contains multiple PEM-encoded keys with a recognized label.
        /// </para>
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   <para>
        ///   The password is incorrect.
        ///   </para>
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <para>
        ///   The base-64 decoded contents of the PEM text from <paramref name="input" />
        ///   do not represent an ASN.1-BER-encoded PKCS#8 EncryptedPrivateKeyInfo structure.
        ///   </para>
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <para>
        ///   The base-64 decoded contents of the PEM text from <paramref name="input" />
        ///   indicate the key is for an algorithm other than the algorithm
        ///   represented by this instance.
        ///   </para>
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <para>
        ///   The base-64 decoded contents of the PEM text from <paramref name="input" />
        ///   represent the key in a format that is not supported.
        ///   </para>
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <para>
        ///   The algorithm-specific key import failed.
        ///   </para>
        /// </exception>
        /// <remarks>
        ///   <para>
        ///   When the base-64 decoded contents of <paramref name="input" /> indicate an algorithm that uses PBKDF1
        ///   (Password-Based Key Derivation Function 1) or PBKDF2 (Password-Based Key Derivation Function 2),
        ///   the password is converted to bytes via the UTF-8 encoding.
        ///   </para>
        ///   <para>
        ///   Unsupported or malformed PEM-encoded objects will be ignored. If multiple supported PEM labels
        ///   are found, an exception is thrown to prevent importing a key when
        ///   the key is ambiguous.
        ///   </para>
        ///   <para>This method supports the <c>ENCRYPTED PRIVATE KEY</c> PEM label.</para>
        /// </remarks>
        public override void ImportFromEncryptedPem(ReadOnlySpan<char> input, ReadOnlySpan<char> password)
        {
            PemKeyImportHelpers.ImportEncryptedPem<char>(input, password, ImportEncryptedPkcs8PrivateKey);
        }

        /// <summary>
        /// Imports an encrypted RFC 7468 PEM-encoded private key, replacing the keys for this object.
        /// </summary>
        /// <param name="input">The PEM text of the encrypted key to import.</param>
        /// <param name="passwordBytes">
        /// The bytes to use as a password when decrypting the key material.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///     <paramref name="input"/> does not contain a PEM-encoded key with a recognized label.
        ///   </para>
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <para>
        ///     <paramref name="input"/> contains multiple PEM-encoded keys with a recognized label.
        ///   </para>
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   <para>
        ///   The password is incorrect.
        ///   </para>
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <para>
        ///   The base-64 decoded contents of the PEM text from <paramref name="input" />
        ///   do not represent an ASN.1-BER-encoded PKCS#8 EncryptedPrivateKeyInfo structure.
        ///   </para>
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <para>
        ///   The base-64 decoded contents of the PEM text from <paramref name="input" />
        ///   indicate the key is for an algorithm other than the algorithm
        ///   represented by this instance.
        ///   </para>
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <para>
        ///   The base-64 decoded contents of the PEM text from <paramref name="input" />
        ///   represent the key in a format that is not supported.
        ///   </para>
        ///   <para>
        ///       -or-
        ///   </para>
        ///   <para>
        ///   The algorithm-specific key import failed.
        ///   </para>
        /// </exception>
        /// <remarks>
        ///   <para>
        ///   The password bytes are passed directly into the Key Derivation Function (KDF)
        ///   used by the algorithm indicated by <c>pbeParameters</c>. This enables compatibility
        ///   with other systems which use a text encoding other than UTF-8 when processing
        ///   passwords with PBKDF2 (Password-Based Key Derivation Function 2).
        ///   </para>
        ///   <para>
        ///   Unsupported or malformed PEM-encoded objects will be ignored. If multiple supported PEM labels
        ///   are found, an exception is thrown to prevent importing a key when
        ///   the key is ambiguous.
        ///   </para>
        ///   <para>This method supports the <c>ENCRYPTED PRIVATE KEY</c> PEM label.</para>
        /// </remarks>
        public override void ImportFromEncryptedPem(ReadOnlySpan<char> input, ReadOnlySpan<byte> passwordBytes)
        {
            PemKeyImportHelpers.ImportEncryptedPem<byte>(input, passwordBytes, ImportEncryptedPkcs8PrivateKey);
        }
    }
}
