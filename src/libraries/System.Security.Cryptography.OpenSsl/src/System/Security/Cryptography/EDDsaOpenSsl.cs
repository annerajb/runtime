// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    public sealed partial class EDDsaOpenSsl : EDDsa
    {
        public EDDsaOpenSsl(EDDsaParameters parameters)
        {
            ThrowIfNotSupported();

            // Make _key be non-null before calling ImportParameters
            _key = new Lazy<SafeEvpPKeyHandle>();
            ImportParameters(parameters);
        }
        /// <summary>
        /// Create an EDDsaOpenSsl from an <see cref="SafeEvpPKeyHandle"/> whose value is an existing
        /// OpenSSL <c>EVP_PKEY*</c>
        /// </summary>
        /// <param name="pkeyHandle">A SafeHandle for an OpenSSL <c>EVP_PKEY*</c></param>
        /// <exception cref="ArgumentNullException"><paramref name="pkeyHandle"/> is <c>null</c></exception>
        /// <exception cref="ArgumentException"><paramref name="pkeyHandle"/> <see cref="SafeHandle.IsInvalid" /></exception>
        /// <exception cref="CryptographicException"><paramref name="pkeyHandle"/> is not a valid enveloped <c>EC_KEY*</c></exception>
        public EDDsaOpenSsl(SafeEvpPKeyHandle pkeyHandle)
        {
            if (pkeyHandle == null)
                throw new ArgumentNullException(nameof(pkeyHandle));
            if (pkeyHandle.IsInvalid)
                throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(pkeyHandle));

            //ThrowIfNotSupported();
            SafeEvpPKeyHandle newKey = Interop.Crypto.EvpPKeyDuplicate(
                 pkeyHandle,
                 Interop.Crypto.EvpAlgorithmId.Ed25519);

            SetKey(newKey);
        }

        /// <summary>
        /// Create an EDDsaOpenSsl from an existing <see cref="IntPtr"/> whose value is an
        /// existing OpenSSL <c>EC_KEY*</c>.
        /// </summary>
        /// <remarks>
        /// This method will increase the reference count of the <c>EC_KEY*</c>, the caller should
        /// continue to manage the lifetime of their reference.
        /// </remarks>
        /// <param name="handle">A pointer to an OpenSSL <c>EC_KEY*</c></param>
        /// <exception cref="ArgumentException"><paramref name="handle" /> is invalid</exception>
        public EDDsaOpenSsl(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
                throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(handle));

            //ThrowIfNotSupported();
            SafeEvpPKeyHandle pkey = new SafeEvpPKeyHandle();//Interop.Crypto.EvpPKeyCreateEdDsa(handle);
            Debug.Assert(!pkey.IsInvalid);

            SetKey(pkey);
        }

        /// <summary>
        /// Obtain a SafeHandle version of an EVP_PKEY* which wraps an EC_KEY* equivalent
        /// to the current key for this instance.
        /// </summary>
        /// <returns>A SafeHandle for the EC_KEY key in OpenSSL</returns>
        public SafeEvpPKeyHandle DuplicateKeyHandle()
        {
            SafeEvpPKeyHandle pkeyHandle = Interop.Crypto.EvpPKeyDuplicate(GetKey(), Interop.Crypto.EvpAlgorithmId.Ed25519);

            try
            {
                //todo test out the dispose /copy /upref been done correctly on line 68
                //// Wrapping our key in an EVP_PKEY will up_ref our key.
                //// When the EVP_PKEY is Disposed it will down_ref the key.
                //// So everything should be copacetic.
                //if (!Interop.Crypto.EvpPkeySetEcKey(pkeyHandle, currentKey))
                //{
                //    throw Interop.Crypto.CreateOpenSslCryptographicException();
                //}

                return pkeyHandle;
            }
            catch
            {
                pkeyHandle.Dispose();
                throw;
            }
        }

        // static partial void ThrowIfNotSupported()
        // {
        //     if (!Interop.OpenSslNoInit.OpenSslIsAvailable)
        //     {
        //         throw new PlatformNotSupportedException(SR.Format(SR.Cryptography_AlgorithmNotSupported, nameof(EDDsaOpenSsl)));
        //     }
        // }
    }
}
