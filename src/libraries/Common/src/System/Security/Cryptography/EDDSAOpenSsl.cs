// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.IO;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class EdDsaImplementation
    {
#endif
        public sealed partial class EDDSAOpenSsl : EDDSA
        {
            // Ed448 maxes out at 114 bytes, so 114  should always be enough
            private const int SignatureStackBufSize = 114;

            private Lazy<SafeEvpPKeyHandle> _key;

        // <summary>
        // Create an ECDsaOpenSsl algorithm with a named curve.
        // </summary>
        // <param name="curve">The <see cref="ECCurve"/> representing the curve.</param>
        // <exception cref="ArgumentNullException">if <paramref name="curve" /> is null.</exception>
        //public EDDSAOpenSsl(ECCurve curve)
        //{
        //    ThrowIfNotSupported();
        //    _key = new SafeEvpPKeyHandle(curve);
        //    ForceSetKeySize(_key.KeySize);
        //}

        /// <summary>
        ///     Create an ECDsaOpenSsl algorithm with a random 128 bit key pair.
        /// </summary>
        public EDDSAOpenSsl() : this(128)
        {
        }

        public EDDSAOpenSsl(int keySize)
        {
            ThrowIfNotSupported();
            base.KeySize = keySize;
            _key = new Lazy<SafeEvpPKeyHandle>(GenerateKey);
        }
        /// <summary>
        /// Set the KeySize without validating against LegalKeySizes.
        /// </summary>
        /// <param name="newKeySize">The value to set the KeySize to.</param>
        private void ForceSetKeySize(int newKeySize)
        {
            // In the event that a key was loaded via ImportParameters, curve name, or an IntPtr/SafeHandle
            // it could be outside of the bounds that we currently represent as "legal key sizes".
            // Since that is our view into the underlying component it can be detached from the
            // component's understanding.  If it said it has opened a key, and this is the size, trust it.
            KeySizeValue = newKeySize;
        }

        public override KeySizes[] LegalKeySizes
        {
            get
            {
                // Return the three sizes that can be explicitly set (for backwards compatibility)
                return new[] {
                    new KeySizes(minSize: 128, maxSize: 128, skipSize: 0),
                    //new KeySizes(minSize: 224, maxSize: 521, skipSize: 0),
                };
            }
        }

            public override byte[] SignHash(byte[] hash)
            {
                if (hash == null)
                    throw new ArgumentNullException(nameof(hash));

                ThrowIfDisposed();
                SafeEvpPKeyHandle key = _key.Value;
                int signatureLength = SignatureStackBufSize;//Interop.Crypto.EcDsaSize(key);

                Span<byte> signDestination = stackalloc byte[SignatureStackBufSize];
                ReadOnlySpan<byte> derSignature = SignHash(hash, signDestination, signatureLength, key);

                byte[] converted = AsymmetricAlgorithmHelpers.ConvertDerToIeee1363(derSignature, KeySize);
                return converted;
            }

#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
            public override bool TrySignHash(ReadOnlySpan<byte> hash, Span<byte> destination, out int bytesWritten)
            {
                return TrySignHashCore(
                    hash,
                    destination,
                    out bytesWritten);
            }

            protected override bool TrySignHashCore(
                ReadOnlySpan<byte> hash,
                Span<byte> destination,
                out int bytesWritten)
#else
            public override bool TrySignHash(ReadOnlySpan<byte> hash, Span<byte> destination, out int bytesWritten)
#endif
            {
                ThrowIfDisposed();
                SafeEvpPKeyHandle key = _key.Value;

                int signatureLength = 64;//Interop.Crypto.EcDsaSize(key);
                Span<byte> signDestination = stackalloc byte[SignatureStackBufSize];


                int encodedSize = 2 * AsymmetricAlgorithmHelpers.BitsToBytes(KeySize);

                if (destination.Length < encodedSize)
                {
                    bytesWritten = 0;
                    return false;
                }

                ReadOnlySpan<byte> derSignature = SignHash(hash, destination, signatureLength, key);
                bytesWritten = signatureLength;//AsymmetricAlgorithmHelpers.ConvertDerToIeee1363(derSignature, KeySize, destination);
                Debug.Assert(bytesWritten == encodedSize);
                return true;
            }

            private static ReadOnlySpan<byte> SignHash(
                ReadOnlySpan<byte> hash,
                Span<byte> destination,
                int signatureLength,
                SafeEvpPKeyHandle key)
            {
                if (signatureLength > destination.Length)
                {
                    Debug.Fail($"Stack-based signDestination is insufficient ({signatureLength} needed)");
                    destination = new byte[signatureLength];
                }
                //todo: move this outside eddsaopenssl.cs since it's generic for openssl digests as evp_pkeys
                int actualLength = Interop.Crypto.EvpDigestSign(key, hash, destination);
                if (actualLength < 0)
                {
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }
                //todo
                Debug.Assert(
                    (int)actualLength <= signatureLength,
                    "EvpDigestSign reported an unexpected signature size",
                    "EvpDigestSign reported signatureSize was {0}, when <= {1} was expected",
                    actualLength,
                    signatureLength);

                return destination.Slice(0, (int)actualLength);
            }

            public override bool VerifyHash(byte[] hash, byte[] signature)
            {
                if (hash == null)
                    throw new ArgumentNullException(nameof(hash));
                if (signature == null)
                    throw new ArgumentNullException(nameof(signature));

                return VerifyHash((ReadOnlySpan<byte>)hash, (ReadOnlySpan<byte>)signature);
            }

#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
            public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature) =>
                VerifyHashCore(hash, signature);

            protected override bool VerifyHashCore(
                ReadOnlySpan<byte> hash,
                ReadOnlySpan<byte> signature)
#else
            public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature)
#endif
            {
                ThrowIfDisposed();

                Span<byte> derSignature = stackalloc byte[SignatureStackBufSize];
                ReadOnlySpan<byte> toVerify = derSignature;

                int expectedBytes = 64;//if ed25519 is 64
                if (signature.Length != expectedBytes)
                {
                    // The input isn't of the right length, so we can't sensibly re-encode it.
                    return false;
                }

                toVerify = derSignature.Slice(0, expectedBytes);

                SafeEvpPKeyHandle key = _key.Value;
                return Interop.Crypto.EvpDigestVerify(key, hash, toVerify);
            }

            //protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm) =>
            //    AsymmetricAlgorithmHelpers.HashData(data, offset, count, hashAlgorithm);

            //protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm) =>
            //    AsymmetricAlgorithmHelpers.HashData(data, hashAlgorithm);

            //protected override bool TryHashData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) =>
            //    AsymmetricAlgorithmHelpers.TryHashData(data, destination, hashAlgorithm, out bytesWritten);

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    FreeKey();
                    _key = null!;
                }

                base.Dispose(disposing);
            }
            private void FreeKey()
        {
            if (_key != null && _key.IsValueCreated)
            {
                SafeEvpPKeyHandle handle = _key.Value;
                handle?.Dispose();
            }
        }
        [System.Diagnostics.CodeAnalysis.MemberNotNull(nameof(_key))]
        private void SetKey(SafeEvpPKeyHandle newKey)
        {
            Debug.Assert(!newKey.IsInvalid);
            FreeKey();
            _key = new Lazy<SafeEvpPKeyHandle>(newKey);

            // Use ForceSet instead of the property setter to ensure that LegalKeySizes doesn't interfere
            // with the already loaded key.
            ForceSetKeySize(128);
        }
        public override int KeySize
            {
                get
                {
                    return base.KeySize;
                }
                set
                {
                    if (KeySize == value)
                        return;

                    // Set the KeySize before FreeKey so that an invalid value doesn't throw away the key
                    base.KeySize = value;

                    ThrowIfDisposed();
                    FreeKey();
                    _key = new Lazy<SafeEvpPKeyHandle>(GenerateKey);
                }
            }

        private SafeEvpPKeyHandle GenerateKey()
        {
            return Interop.Crypto.EdDsaGenerateKey();
        }

        //public override void ImportParameters(ECParameters parameters)
        //{
        //    ThrowIfDisposed();
        //    _key.ImportParameters(parameters);
        //    ForceSetKeySize(_key.KeySize);
        //}

        //public override ECParameters ExportExplicitParameters(bool includePrivateParameters)
        //{
        //    ThrowIfDisposed();
        //    return ECOpenSsl.ExportExplicitParameters(_key.Value, includePrivateParameters);
        //}

        //public override ECParameters ExportParameters(bool includePrivateParameters)
        //{
        //    ThrowIfDisposed();
        //    return ECOpenSsl.ExportParameters(_key.Value, includePrivateParameters);
        //}

        public override void ImportEncryptedPkcs8PrivateKey(
                ReadOnlySpan<byte> passwordBytes,
                ReadOnlySpan<byte> source,
                out int bytesRead)
            {
                ThrowIfDisposed();
                base.ImportEncryptedPkcs8PrivateKey(passwordBytes, source, out bytesRead);
            }

            public override void ImportEncryptedPkcs8PrivateKey(
                ReadOnlySpan<char> password,
                ReadOnlySpan<byte> source,
                out int bytesRead)
            {
                ThrowIfDisposed();
                base.ImportEncryptedPkcs8PrivateKey(password, source, out bytesRead);
            }

            private void ThrowIfDisposed()
            {
                if (_key == null)
                {
                    throw new ObjectDisposedException(
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
                        nameof(EDDSA)
#else
                        nameof(EDDSAOpenSsl)
#endif
                    );
                }
            }
        private SafeEvpPKeyHandle GetKey()
        {
            ThrowIfDisposed();

            SafeEvpPKeyHandle key = _key.Value;

            if (key == null || key.IsInvalid)
            {
                throw new CryptographicException(SR.Cryptography_OpenInvalidHandle);
            }

            return key;
        }
        static partial void ThrowIfNotSupported();
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
