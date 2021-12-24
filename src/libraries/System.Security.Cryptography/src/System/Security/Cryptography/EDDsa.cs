// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Internal.Cryptography;
using System.Runtime.Versioning;
using System.Formats.Asn1;

namespace System.Security.Cryptography
{
    public abstract partial class EDDsa : AsymmetricAlgorithm
    {
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
        public override bool TryExportPkcs8PrivateKey(Span<byte> destination, out int bytesWritten)
        {
            AsnWriter writer = WritePkcs8();
            return writer.TryEncode(destination, out bytesWritten);
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
    }
}
