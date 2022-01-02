// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    /// <summary>
    /// An elliptic curve.
    /// </summary>
    /// <remarks>
    /// The CurveType property determines whether the curve is a named curve or an explicit curve
    /// which is either a prime curve or a characteristic-2 curve.
    /// </remarks>
    [DebuggerDisplay("EDCurve: {Oid}")]
    public partial struct EDCurve
    {
        private Oid _oid;
        /// <summary>
        /// The Oid representing the named curve. Applies only to Named curves.
        /// </summary>
        public Oid Oid
        {
            get => _oid;
            private set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(Oid));

                if (string.IsNullOrEmpty(value.Value) && string.IsNullOrEmpty(value.FriendlyName))
                    throw new ArgumentException(SR.Cryptography_InvalidCurveOid);

                _oid = value;
            }
        }

        /// <summary>
        /// Create a curve from the given cref="Oid".
        /// </summary>
        /// <param name="curveOid">The Oid to use.</param>
        /// <returns>An EDCurve representing a named curve.</returns>
        public static EDCurve CreateFromOid(Oid curveOid)
        {
            EDCurve curve = default;
            curve.Oid = curveOid;
            return curve;
        }

        /// <summary>
        /// Create a curve from the given cref="Oid" friendly name.
        /// </summary>
        /// <param name="oidFriendlyName">The Oid friendly name to use.</param>
        /// <returns>An EDCurve representing a named curve.</returns>
        public static EDCurve CreateFromFriendlyName(string oidFriendlyName)
        {
            if (oidFriendlyName == null)
            {
                throw new ArgumentNullException(nameof(oidFriendlyName));
            }
            return EDCurve.CreateFromValueAndName(null, oidFriendlyName);
        }

        /// <summary>
        /// Create a curve from the given cref="Oid" value.
        /// </summary>
        /// <param name="oidValue">The Oid value to use.</param>
        /// <returns>An EDCurve representing a named curve.</returns>
        public static EDCurve CreateFromValue(string oidValue)
        {
            if (oidValue == null)
            {
                throw new ArgumentNullException(nameof(oidValue));
            }
            return EDCurve.CreateFromValueAndName(oidValue, null);
        }

        private static EDCurve CreateFromValueAndName(string? oidValue, string? oidFriendlyName)
        {
            Oid? oid = null;

            if (oidValue == null && oidFriendlyName != null)
            {
                try
                {
                    oid = Oid.FromFriendlyName(oidFriendlyName, OidGroup.PublicKeyAlgorithm);
                }
                catch (CryptographicException)
                {
                }
            }

            oid ??= new Oid(oidValue, oidFriendlyName);
            return EDCurve.CreateFromOid(oid);
        }
    }
}
