// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.Security.Cryptography.Asn1;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    public partial class EDDsa : AsymmetricAlgorithm
    {
        public static new partial EDDsa Create() => new EDDsaImplementation.EDDsaOpenSsl();
    }

    internal static partial class EDDsaImplementation
    {
#endif
    public sealed partial class EDDsaOpenSsl : EDDsa
    {
        // Ed448 maxes out at 114 bytes, so 114  should always be enough
        private const int SignatureStackBufSize = 114;

        private Lazy<SafeEvpPKeyHandle> _key;

        /// <summary>
        ///     Create an EDDsaOpenSsl algorithm with a random 128 bit key pair.
        /// </summary>
        public EDDsaOpenSsl() : this(128)
        {
        }

        public EDDsaOpenSsl(int keySize)
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
            int actualLength = 10;//Interop.Crypto.EvpDigestSign(key, hash, destination);
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
            return false;//;Interop.Crypto.EvpDigestVerify(key, hash, toVerify);
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

        public override void ImportPkcs8PrivateKey(ReadOnlySpan<byte> source, out int bytesRead)
        {
            ThrowIfDisposed();

            ImportPkcs8PrivateKey(source, checkAlgorithm: true, out bytesRead);
        }

        private void ImportPkcs8PrivateKey(ReadOnlySpan<byte> source, bool checkAlgorithm, out int bytesRead)
        {
            int read;

            if (checkAlgorithm)
            {
                read = EDDsaKeyFormatHelper.CheckPkcs8(source);
            }
            else
            {
                read = source.Length;
            }
            //todo unit test this well... since it seemd to fail when calling import spki
            SafeEvpPKeyHandle newKey = Interop.Crypto.DecodePkcs8PrivateKey(
                source.Slice(0, read),
                Interop.Crypto.EvpAlgorithmId.Ed25519);

            Debug.Assert(!newKey.IsInvalid);
            SetKey(newKey);
            bytesRead = read;
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
            ForceSetKeySize(8 * 32);
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
            return new SafeEvpPKeyHandle();//Interop.Crypto.EdDsaGenerateKey();
        }

        public override void ImportParameters(EDDsaParameters parameters)
        {
            ThrowIfDisposed();
            if (parameters.PrivateKey != null)
            {
                AsnWriter writer = EDDsaKeyFormatHelper.WritePkcs8PrivateKey(parameters);
                ArraySegment<byte> pkcs8 = writer.RentAndEncode();

                try
                {
                    ImportPkcs8PrivateKey(pkcs8, checkAlgorithm: false, out _);
                }
                finally
                {
                    CryptoPool.Return(pkcs8);
                }
            }
            else
            {
                AsnWriter writer = EDDsaKeyFormatHelper.WriteSubjectPublicKeyInfo(parameters);
                ArraySegment<byte> spki = writer.RentAndEncode();

                try
                {
                    ImportSubjectPublicKeyInfo(spki, checkAlgorithm: false, out _);
                }
                finally
                {
                    CryptoPool.Return(spki);
                }
            }
        }
        public override void ImportSubjectPublicKeyInfo(
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            ThrowIfDisposed();

            ImportSubjectPublicKeyInfo(source, checkAlgorithm: true, out bytesRead);
        }
        private void ImportSubjectPublicKeyInfo(
            ReadOnlySpan<byte> source,
            bool checkAlgorithm,
            out int bytesRead)
        {
            int read;

            if (checkAlgorithm)
            {
                read = EDDsaKeyFormatHelper.CheckSubjectPublicKeyInfo(source);
            }
            else
            {
                read = source.Length;
            }
            //unit test this really well
            SafeEvpPKeyHandle newKey = Interop.Crypto.DecodeSubjectPublicKeyInfo(
                source.Slice(0, read),
                Interop.Crypto.EvpAlgorithmId.Ed25519);

            Debug.Assert(!newKey.IsInvalid);
            SetKey(newKey);
            bytesRead = read;
        }
        private delegate T ExportPrivateKeyFunc<T>(ReadOnlyMemory<byte> pkcs8, ReadOnlyMemory<byte> pkcs1);
        private T ExportPrivateKey<T>(ExportPrivateKeyFunc<T> exporter)
        {
            // It's entirely possible that this line will cause the key to be generated in the first place.
            SafeEvpPKeyHandle key = GetKey();

            ArraySegment<byte> p8 = Interop.Crypto.EvpPKeyGetRawPrivateKey(key);
            try
            {
                ReadOnlyMemory<byte> pkcs1 = VerifyPkcs8(p8);
                return exporter(p8, pkcs1);
            }
            finally
            {
                CryptoPool.Return(p8);
            }
        }

        private static ReadOnlyMemory<byte> VerifyPkcs8(ReadOnlyMemory<byte> pkcs8)
        {
            // OpenSSL 1.1.1 will export RSA public keys as a PKCS#8, but this makes a broken structure.
            //
            // So, crack it back open.  If we can walk the payload it's valid, otherwise throw the
            // "there's no private key" exception.

            try
            {
                ReadOnlyMemory<byte> pkcs1Priv = EDDsaKeyFormatHelper.ReadPkcs8(pkcs8, out int read);
                Debug.Assert(read == pkcs8.Length);
                if (pkcs1Priv.Length != 32)
                {
                    throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
                }
                return pkcs1Priv;
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey, ex);
            }
        }
        public override EDDsaParameters ExportParameters(bool includePrivateParameters)
        {
            SafeEvpPKeyHandle key = GetKey();
            EDDsaParameters ret;
            if (includePrivateParameters)
            {
                ArraySegment<byte> keyraw = Interop.Crypto.EvpPKeyGetRawPrivateKey(key);
                ret = new(){
                    PrivateKey = keyraw.ToArray(),
                };
            }else {
                Span<byte> dest = stackalloc byte[32];
                int publen =  Interop.Crypto.EvpPKeyGetRawPublicKey(key, dest);
                if (publen <= 0)
                {
                    throw new CryptographicException();
                }
                ret = new() {
                    PublicKey = dest.ToArray()
                };
            }
            return ret;
            // if (includePrivateParameters)
            // {
            //     return ExportPrivateKey(
            //         static (pkcs8, pkcs1) =>
            //         {
            //             AlgorithmIdentifierAsn algId = default;
            //             EDDsaParameters ret;
            //             EDDsaKeyFormatHelper.FromPkcs1PrivateKey(pkcs1, in algId, out ret);
            //             return ret;
            //         });
            // }

            // return ExportPublicKey(
            //     static spki =>
            //     {
            //         EDDsaParameters ret;
            //         EDDsaKeyFormatHelper.ReadSubjectPublicKeyInfo(
            //             spki.Span,
            //             out int read,
            //             out ret);

            //         Debug.Assert(read == spki.Length);
            //         return ret;
            //     });
        }
        public override byte[] ExportSubjectPublicKeyInfo()
        {
            return ExportPublicKey(static spki => spki.ToArray());
        }
        public override bool TryExportSubjectPublicKeyInfo(Span<byte> destination, out int bytesWritten)
        {
            return TryExportPublicKey(
                transform: null,
                destination,
                out bytesWritten);
        }
        private T ExportPublicKey<T>(Func<ReadOnlyMemory<byte>, T> exporter)
        {
            // It's entirely possible that this line will cause the key to be generated in the first place.
            SafeEvpPKeyHandle key = GetKey();

            ArraySegment<byte> spki = Interop.Crypto.RentEncodeSubjectPublicKeyInfo(key);

            try
            {
                return exporter(spki);
            }
            finally
            {
                CryptoPool.Return(spki);
            }
        }
        private bool TryExportPublicKey(
            Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>? transform,
            Span<byte> destination,
            out int bytesWritten)
        {
            // It's entirely possible that this line will cause the key to be generated in the first place.
            SafeEvpPKeyHandle key = GetKey();

            ArraySegment<byte> spki = Interop.Crypto.RentEncodeSubjectPublicKeyInfo(key);

            try
            {
                ReadOnlyMemory<byte> data = spki;

                if (transform != null)
                {
                    data = transform(data);
                }

                return data.Span.TryCopyToDestination(destination, out bytesWritten);
            }
            finally
            {
                CryptoPool.Return(spki);
            }
        }
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
                    nameof(EDDsa)
#else
                    nameof(EDDsaOpenSsl)
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
