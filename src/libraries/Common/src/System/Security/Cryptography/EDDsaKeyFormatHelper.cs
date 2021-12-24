// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    internal static partial class EDDsaKeyFormatHelper
    {
        private static readonly string[] s_validOids =
        {
            Oids.Ed25519,
        };
        //todo rename to pkcs8?
        internal static void FromPkcs1PrivateKey(
            ReadOnlyMemory<byte> keyData,
            in AlgorithmIdentifierAsn algId,
            out EDDsaParameters ret)
        {
            PrivateKeyInfoAsn key = PrivateKeyInfoAsn.Decode(keyData, AsnEncodingRules.BER);

            if (!algId.HasNullEquivalentParameters())
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // The modulus size determines the encoded output size of the CRT parameters.
            ret = new EDDsaParameters
            {
                Key = key.PrivateKey.ToArray(),
            };
        }

        internal static void ReadEDDsaPublicKey(
            ReadOnlyMemory<byte> keyData,
            in AlgorithmIdentifierAsn algId,
            out EDDsaParameters ret)
        {
            SubjectPublicKeyInfoAsn key = SubjectPublicKeyInfoAsn.Decode(keyData, AsnEncodingRules.BER);

            ret = new EDDsaParameters
            {
                Key = key.SubjectPublicKey.ToArray(),
            };
        }
        /// <summary>
        ///   Checks that a Pkcs8PrivateKeyInfo represents an EDDsa key.
        /// </summary>
        /// <returns>The number of bytes read from <paramref name="source"/>.</returns>
        internal static unsafe int CheckPkcs8(ReadOnlySpan<byte> source)
        {
            int bytesRead;

            fixed (byte* ptr = source)
            {
                using (MemoryManager<byte> manager = new PointerMemoryManager<byte>(ptr, source.Length))
                {
                    _ = ReadPkcs8(manager.Memory, out bytesRead);
                }
            }

            return bytesRead;
        }
        internal static void ReadEDDsaPublicKey(
            ReadOnlyMemory<byte> keyData,
            out int bytesRead)
        {
            int read;

            try
            {
                AsnValueReader reader = new AsnValueReader(keyData.Span, AsnEncodingRules.DER);
                read = reader.PeekEncodedValue().Length;
                RSAPublicKeyAsn.Decode(keyData, AsnEncodingRules.BER);
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }

            bytesRead = read;
        }

        internal static void ReadSubjectPublicKeyInfo(
            ReadOnlySpan<byte> source,
            out int bytesRead,
            out EDDsaParameters key)
        {
            KeyFormatHelper.ReadSubjectPublicKeyInfo<EDDsaParameters>(
                s_validOids,
                source,
                ReadEDDsaPublicKey,
                out bytesRead,
                out key);
        }

        internal static ReadOnlyMemory<byte> ReadSubjectPublicKeyInfo(
             ReadOnlyMemory<byte> source,
             out int bytesRead)
        {
            return KeyFormatHelper.ReadSubjectPublicKeyInfo(
                s_validOids,
                source,
                out bytesRead);
        }

        /// <summary>
        ///   Checks that a SubjectPublicKeyInfo represents an RSA key.
        /// </summary>
        /// <returns>The number of bytes read from <paramref name="source"/>.</returns>
        internal static unsafe int CheckSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
        {
            int bytesRead;

            fixed (byte* ptr = source)
            {
                using (MemoryManager<byte> manager = new PointerMemoryManager<byte>(ptr, source.Length))
                {
                    _ = ReadSubjectPublicKeyInfo(manager.Memory, out bytesRead);
                }
            }

            return bytesRead;
        }

        public static void ReadPkcs8(
            ReadOnlySpan<byte> source,
            out int bytesRead,
            out EDDsaParameters key)
        {
            KeyFormatHelper.ReadPkcs8<EDDsaParameters>(
                s_validOids,
                source,
                FromPkcs1PrivateKey,
                out bytesRead,
                out key);
        }

        internal static ReadOnlyMemory<byte> ReadPkcs8(
            ReadOnlyMemory<byte> source,
            out int bytesRead)
        {
            return KeyFormatHelper.ReadPkcs8(
                s_validOids,
                source,
                out bytesRead);
        }


        internal static AsnWriter WriteSubjectPublicKeyInfo(ReadOnlySpan<byte> pkcs1PublicKey)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            writer.PushSequence();
            WriteAlgorithmIdentifier(writer);
            writer.WriteBitString(pkcs1PublicKey);
            writer.PopSequence();

            return writer;
        }

        internal static AsnWriter WriteSubjectPublicKeyInfo(in EDDsaParameters EDDsaParameters)
        {
            AsnWriter pkcs1PublicKey = WritePkcs1PublicKey(EDDsaParameters);
            byte[] rented = CryptoPool.Rent(pkcs1PublicKey.GetEncodedLength());

            if (!pkcs1PublicKey.TryEncode(rented, out int written))
            {
                Debug.Fail("TryEncode failed with a presized buffer");
                throw new CryptographicException();
            }

            AsnWriter ret = WriteSubjectPublicKeyInfo(rented.AsSpan(0, written));

            // Only public key data data
            CryptoPool.Return(rented, clearSize: 0);
            return ret;
        }

        internal static AsnWriter WritePkcs8PrivateKey(
            ReadOnlySpan<byte> pkcs1PrivateKey,
            AsnWriter? copyFrom=null)
        {
            Debug.Assert(copyFrom == null || pkcs1PrivateKey.IsEmpty);

            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);

            using (writer.PushSequence())
            {
                // Version 0 format (no attributes)
                writer.WriteInteger(0);
                WriteAlgorithmIdentifier(writer);

                if (copyFrom != null)
                {
                    using (writer.PushOctetString())
                    {
                        copyFrom.CopyTo(writer);
                    }
                }
                else
                {
                    writer.WriteOctetString(pkcs1PrivateKey);
                }
            }

            return writer;
        }
        //
        internal static AsnWriter WritePkcs8PrivateKey(in EDDsaParameters EDDsaParameters, AttributeAsn[]? attributes = null)
        {
            if (EDDsaParameters.Key == null)
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }
            //AsnWriter algorithmIdentifier = WriteAlgorithmIdentifier(EDDsaParameters);
            //AsnWriter ecPrivateKey = WriteEcPrivateKey(EDDsaParameters, includeDomainParameters: false);

            //KeyFormatHelper.WritePkcs8(algorithmIdentifier, ecPrivateKey, attributeWriter);

            return WritePkcs8PrivateKey(EDDsaParameters.Key);
        }

        private static void WriteAlgorithmIdentifier(AsnWriter writer)
        {
            writer.PushSequence();

            writer.WriteObjectIdentifier(Oids.Ed25519);

            writer.PopSequence();
        }

        internal static AsnWriter WritePkcs1PublicKey(in EDDsaParameters EDDsaParameters)
        {
            if (EDDsaParameters.Key == null)
            {
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
            }

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteKeyParameterInteger(EDDsaParameters.Key);
            writer.PopSequence();

            return writer;
        }

        internal static AsnWriter WritePkcs1PrivateKey(in EDDsaParameters EDDsaParameters)
        {
            if (EDDsaParameters.Key == null)
            {
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
            }

            if (EDDsaParameters.Key == null)
            {
                throw new CryptographicException(SR.Cryptography_NotValidPrivateKey);
            }

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            writer.PushSequence();

            // Format version 0
            writer.WriteInteger(0);
            writer.WriteKeyParameterInteger(EDDsaParameters.Key);

            writer.PopSequence();
            return writer;
        }
    }
}
