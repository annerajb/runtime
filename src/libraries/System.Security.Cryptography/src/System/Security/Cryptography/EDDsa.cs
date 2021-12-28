// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Internal.Cryptography;
using System.Runtime.Versioning;
using System.Formats.Asn1;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Represents the abstract class from which EdDsa asymmetric
    /// algorithms can inherit from.
    /// </summary>
    public abstract partial class EDDsa : AsymmetricAlgorithm
    {
        private static readonly string[] s_validOids =
        {
            Oids.Ed25519,
        };
        protected EDDsa() { }
        public static new partial EDDsa Create();
        public static partial EDDsa Create(EDDsaParameters parameters);
        //protected  byte[] HashData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) => throw DerivedClassMustOverride();
        //protected  byte[] HashData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) => throw DerivedClassMustOverride();
        /// <summary>
        /// When overridden in a derived class, imports the specified parameters.
        /// </summary>
        /// <param name="parameters">The curve parameters.</param>
        /// <exception cref="NotSupportedException">
        /// A derived class has not provided an implementation.
        /// </exception>
        public abstract void ImportParameters(EDDsaParameters parameters);
        /// <summary>
        /// Imports the public/private keypair from a PKCS#8 PrivateKeyInfo structure
        /// after decryption, replacing the keys for this object.
        /// </summary>
        /// <param name="source">The bytes of a PKCS#8 PrivateKeyInfo structure in the ASN.1-BER encoding.</param>
        /// <param name="bytesRead">
        /// When this method returns, contains a value that indicates the number
        /// of bytes read from <paramref name="source" />. This parameter is treated as uninitialized.
        /// </param>
        /// <exception cref="NotSupportedException">
        /// A derived class has not provided an implementation for <see cref="ImportParameters" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// <p>
        ///   The contents of <paramref name="source" /> do not represent an ASN.1-BER-encoded
        ///   PKCS#8 PrivateKeyInfo structure.
        /// </p>
        /// <p>-or-</p>
        /// <p>
        ///   The contents of <paramref name="source" /> indicate the key is for an algorithm
        ///   other than the algorithm represented by this instance.
        /// </p>
        /// <p>-or-</p>
        /// <p>The contents of <paramref name="source" /> represent the key in a format that is not supported.</p>
        /// <p>-or-</p>
        /// <p>
        ///   The algorithm-specific key import failed.
        /// </p>
        /// </exception>
        /// <remarks>
        /// This method only supports the binary (BER/CER/DER) encoding of PrivateKeyInfo.
        /// If the value is Base64-encoded, the caller must Base64-decode the contents before calling this method.
        /// If the value is PEM-encoded, <see cref="ImportFromPem" /> should be used.
        /// </remarks>
        public override unsafe void ImportPkcs8PrivateKey(
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            KeyFormatHelper.ReadPkcs8<EDDsaParameters>(
                s_validOids,
                source,
                EDDsaKeyFormatHelper.FromEDDsaPrivateKey,
                out int localRead,
                out EDDsaParameters key);

            fixed (byte* privPin = key.Key)
            {
                try
                {
                    ImportParameters(key);
                    bytesRead = localRead;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key.Key);
                }
            }
        }
        public override bool TryExportPkcs8PrivateKey(Span<byte> destination, out int bytesWritten)
        {
            AsnWriter writer = WritePkcs8();
            return writer.TryEncode(destination, out bytesWritten);
        }
        public override bool TryExportSubjectPublicKeyInfo(
            Span<byte> destination,
            out int bytesWritten)
        {
            AsnWriter writer = WriteSubjectPublicKeyInfo();
            return writer.TryEncode(destination, out bytesWritten);
        }
        private AsnWriter WriteSubjectPublicKeyInfo()
        {
            EDDsaParameters dsaParameters = ExportParameters(false);
            return EDDsaKeyFormatHelper.WriteSubjectPublicKeyInfo(dsaParameters);
        }
        private unsafe AsnWriter WritePkcs8()
        {
            EDDsaParameters dsaParameters = ExportParameters(true);

            fixed (byte* privPin = dsaParameters.Key)
            {
                try
                {
                    return EDDsaKeyFormatHelper.WritePkcs8PrivateKey(dsaParameters);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(dsaParameters.Key);
                }
            }
        }
        public abstract bool VerifyHash(byte[] hash, byte[] signature);
        public virtual bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature) => VerifyHashCore(hash, signature);
        public virtual bool TrySignHash(ReadOnlySpan<byte> hash, Span<byte> destination, out int bytesWritten)
            => TrySignHashCore(hash, destination, out bytesWritten);
        public override string? KeyExchangeAlgorithm => null;
        public override string SignatureAlgorithm => "EDDsa";
        /// <summary>
        ///   Attempts to create the EDDsa signature for the specified hash value in the indicated format
        ///   into the provided buffer.
        /// </summary>
        /// <param name="hash">The hash value to sign.</param>
        /// <param name="destination">The buffer to receive the signature.</param>
        /// <param name="bytesWritten">
        ///   When this method returns, contains a value that indicates the number of bytes written to
        ///   <paramref name="destination"/>. This parameter is treated as uninitialized.
        /// </param>
        /// <returns>
        ///   <see langword="true"/> if <paramref name="destination"/> is big enough to receive the signature;
        ///   otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred in the signing operation.
        /// </exception>
        protected virtual bool TrySignHashCore(
            ReadOnlySpan<byte> hash,
            Span<byte> destination,
            out int bytesWritten)
        {
            // This method is expected to be overriden with better implementation

            // The only available implementation here is abstract method, use it
            byte[] result = SignHash(hash.ToArray());
            return Helpers.TryCopyToDestination(result, destination, out bytesWritten);
        }

        /// <summary>
        ///   Verifies that a digital signature is valid for the provided hash.
        /// </summary>
        /// <param name="hash">The signed hash.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>
        ///   <see langword="true"/> if the digital signature is valid for the provided data; otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///   An error occurred in the verification operation.
        /// </exception>
        protected virtual bool VerifyHashCore(
            ReadOnlySpan<byte> hash,
            ReadOnlySpan<byte> signature)
        {
            // The only available implementation here is abstract method, use it
            return VerifyHash(hash.ToArray(), signature.ToArray());
        }
        public abstract byte[] SignHash(byte[] hash);

        /// <summary>
        /// When overridden in a derived class, exports the named or explicit for an EDDsaParameters.
        /// </summary>
        /// <param name="includePrivateParameters">
        ///   <see langword="true" /> to include private parameters, otherwise, <see langword="false" />.
        /// </param>
        /// <exception cref="NotSupportedException">
        /// A derived class has not provided an implementation.
        /// </exception>
        /// <returns>The exported parameters.</returns>
        public abstract EDDsaParameters ExportParameters(bool includePrivateParameters);

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
            // Implementation has been pushed down to AsymmetricAlgorithm. The
            // override remains for compatibility.
            base.ImportFromPem(input);
        }
    }
}
