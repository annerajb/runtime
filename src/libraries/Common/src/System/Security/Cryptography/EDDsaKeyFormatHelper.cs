// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
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
                PrivateKey = key.PrivateKey.ToArray(),
            };
        }
        //public is suppose to include asn and the spki asn oid structure
        internal static void ReadEDDsaPublicKey(
            ReadOnlyMemory<byte> keyData,
            in AlgorithmIdentifierAsn algId,
            out EDDsaParameters ret)
        {
            if (keyData.Length != 32)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
            ret = new EDDsaParameters
            {
                PublicKey = keyData.ToArray()
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
            bytesRead = 0;
            if (keyData.Length == 32)
            {
                bytesRead = keyData.Length;
            }
            //eddsa are opaque values so there is no inner structure inside the key not even a sequence
            return;
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
            ReadOnlyMemory<byte> keycurve = KeyFormatHelper.ReadPkcs8(
                s_validOids,
                source,
                out bytesRead);
            AsnValueReader reader = new AsnValueReader(keycurve.Span, AsnEncodingRules.BER);
            //the raw key bytes are inside the octet string of the octet string
            byte[] key = reader.ReadOctetString();
            return key;
        }

        internal static unsafe EDDsaParameters FromEDDsaPrivateKey(ReadOnlySpan<byte> key, out int bytesRead)
        {
            try
            {
                AsnDecoder.ReadEncodedValue(
                    key,
                    AsnEncodingRules.BER,
                    out _,
                    out _,
                    out int firstValueLength);

                fixed (byte* ptr = &MemoryMarshal.GetReference(key))
                {
                    using (MemoryManager<byte> manager = new PointerMemoryManager<byte>(ptr, firstValueLength))
                    {
                        AlgorithmIdentifierAsn algId = default;
                        FromEDDsaPrivateKey(manager.Memory, algId, out EDDsaParameters ret);
                        bytesRead = firstValueLength;
                        return ret;
                    }
                }
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }
        internal static void FromEDDsaPrivateKey(
            ReadOnlyMemory<byte> keyData,
            in AlgorithmIdentifierAsn algId,
            out EDDsaParameters ret)
        {
            //asn parsing of sequence and privatekey
            PrivateKeyInfoAsn key = PrivateKeyInfoAsn.Decode(keyData, AsnEncodingRules.BER);
            FromEDDsaPrivateKey(key, algId, out ret);
        }
        internal static void FromEDDsaPrivateKey(
            PrivateKeyInfoAsn key,
            in AlgorithmIdentifierAsn algId,
            out EDDsaParameters ret)
        {
            if (key.Version != 0)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
            ret = new EDDsaParameters
            {
                PrivateKey = key.PrivateKey.ToArray(),
            };
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

            // This is public key data dowe need this?
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
            if (EDDsaParameters.PrivateKey == null)
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }
            AsnWriter algorithmIdentifier = WriteAlgorithmIdentifier(EDDsaParameters);
            AsnWriter edPrivateKey = WriteEDDsaPrivateKey(EDDsaParameters, includeDomainParameters: false);
            //attributesWriter = attributes
            //TODO: attributes are allowed irc but not parameters
            return KeyFormatHelper.WritePkcs8(algorithmIdentifier, edPrivateKey, null);

            //return WritePkcs8PrivateKey(EDDsaParameters.PrivateKey);
        }
        private static AsnWriter WriteEDDsaPrivateKey(in EDDsaParameters ecParameters, bool includeDomainParameters)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            writer.WriteOctetString(ecParameters.PrivateKey);

            return writer;
        }

        private static AsnWriter WriteAlgorithmIdentifier(in EDDsaParameters edParameters)
        {

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            WriteAlgorithmIdentifier(writer);

            return writer;
        }
        private static void WriteAlgorithmIdentifier(AsnWriter writer)
        {
            writer.PushSequence();

            writer.WriteObjectIdentifier(Oids.Ed25519);

            writer.PopSequence();
        }

        internal static AsnWriter WritePkcs1PublicKey(in EDDsaParameters EDDsaParameters)
        {
            if (EDDsaParameters.PublicKey == null)
            {
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
            }

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteKeyParameterInteger(EDDsaParameters.PublicKey);
            writer.PopSequence();

            return writer;
        }

        internal static AsnWriter WritePkcs1PrivateKey(in EDDsaParameters EDDsaParameters)
        {
            if (EDDsaParameters.PrivateKey == null)
            {
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
            }

            if (EDDsaParameters.PrivateKey == null)
            {
                throw new CryptographicException(SR.Cryptography_NotValidPrivateKey);
            }

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

            writer.PushSequence();

            // Format version 0
            writer.WriteInteger(0);
            writer.WriteKeyParameterInteger(EDDsaParameters.PrivateKey);

            writer.PopSequence();
            return writer;
        }
    }
}
