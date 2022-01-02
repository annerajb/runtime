// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography.EdDsa.Tests;
using Xunit;

namespace System.Security.Cryptography.Tests
{
    [SkipOnPlatform(TestPlatforms.Browser, "Not supported on Browser")]
    public static class EDDsaACreateTests
    {
        [Fact]
        public static void CreateWithParameters_1032()
        {
            CreateWithParameters(EDDsaTestData.GetNistP256ExplicitTestData());
        }

        [Fact]
        public static void CreateWithParameters_UnusualExponent()
        {
            CreateWithParameters(EDDsaTestData.GetNistP256ExplicitTestData());
        }

        [Fact]
        public static void CreateWithParameters_2048()
        {
            CreateWithParameters(EDDsaTestData.GetNistP256ExplicitTestData());
        }

        private static void CreateWithParameters(EDDsaParameters parameters)
        {
            EDDsaParameters exportedPrivate;

            using (EDDsa EDDsa = EDDsa.Create(parameters))
            {
                exportedPrivate = EDDsa.ExportParameters(true);
            }

            EDDsaImportExportTests.AssertKeyEquals(parameters, exportedPrivate);
        }

        [Fact]
        public static void CreateWithInvalidParameters()
        {
            EDDsaParameters parameters = EDDsaTestData.GetNistP256ExplicitTestData();
            parameters.Key = null;
            Assert.Throws<CryptographicException>(() => EDDsa.Create(parameters));
        }
    }
}
