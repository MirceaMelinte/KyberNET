namespace KyberNET.Testing.Kat;

using System.Reflection;
using System.Runtime.CompilerServices;
using Constants;
using Internal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public class BouncyCastleCrossValidationTest
{
    private static readonly MethodInfo BouncyCastleInternalGenerateKeyPair = typeof(MLKemKeyPairGenerator)
        .GetMethod("InternalGenerateKeyPair", BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static readonly MethodInfo BouncyCastleInternalEncapsulate = typeof(MLKemPublicKeyParameters)
        .GetMethod("InternalEncapsulate", BindingFlags.Instance | BindingFlags.NonPublic)!;

    private static void CrossValidate(KyberParameter myParam, MLKemParameters bouncyCastleParam, int iterations, CancellationToken cancellationToken = default)
    {
        var random = new SecureRandom();

        for (var i = 0; i < iterations; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            var z = new byte[32];
            var d = new byte[32];
            var message = new byte[32];
            random.NextBytes(z);
            random.NextBytes(d);
            random.NextBytes(message);

            // Arrange
            var bouncyCastleGenerator = new MLKemKeyPairGenerator();
            bouncyCastleGenerator.Init(new MLKemKeyGenerationParameters(random, bouncyCastleParam));
            var bouncyCastleKeyPair = (AsymmetricCipherKeyPair)BouncyCastleInternalGenerateKeyPair.Invoke(bouncyCastleGenerator, [d, z])!;
            var bouncyCastleEncapsulationKey = (MLKemPublicKeyParameters)bouncyCastleKeyPair.Public;
            var bouncyCastleDecapsulationKey = (MLKemPrivateKeyParameters)bouncyCastleKeyPair.Private;

            var keyPair = KyberKeyGenerator.Generate(myParam, z, d);

            // Assert
            CollectionAssert.AreEqual(bouncyCastleEncapsulationKey.GetEncoded(), keyPair.EncapsulationKey.FullBytes);
            CollectionAssert.AreEqual(bouncyCastleDecapsulationKey.GetEncoded(), keyPair.DecapsulationKey.FullBytes);

            // Arrange
            var savedMessage = (byte[])message.Clone();
            var bouncyCastleEncapsulationResult = (ITuple)BouncyCastleInternalEncapsulate.Invoke(bouncyCastleEncapsulationKey, [savedMessage])!;
            var bouncyCastleCipherText = (byte[])bouncyCastleEncapsulationResult[0]!;
            var bouncyCastleSharedSecret = (byte[])bouncyCastleEncapsulationResult[1]!;

            var result = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, message);

            // Assert
            CollectionAssert.AreEqual(bouncyCastleSharedSecret, result.SharedSecretKey);
            CollectionAssert.AreEqual(bouncyCastleCipherText, result.CipherText.FullBytes);

            // Act
            var recoveredSharedSecret = keyPair.DecapsulationKey.Decapsulate(result.CipherText);

            // Assert
            CollectionAssert.AreEqual(result.SharedSecretKey, recoveredSharedSecret);
        }
    }

    [TestClass]
    public class Comprehensive
        : BouncyCastleCrossValidationTest
    {
        public TestContext TestContext { get; set; } = null!;

        [TestMethod, TestCategory("BouncyCastle"), TestCategory("Comprehensive")]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void MlKem512_10000Iterations()
        {
            CrossValidate(KyberParameter.MlKem512, MLKemParameters.ml_kem_512, 10_000, TestContext.CancellationTokenSource.Token);
        }

        [TestMethod, TestCategory("BouncyCastle"), TestCategory("Comprehensive")]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void MlKem768_10000Iterations()
        {
            CrossValidate(KyberParameter.MlKem768, MLKemParameters.ml_kem_768, 10_000, TestContext.CancellationTokenSource.Token);
        }

        [TestMethod, TestCategory("BouncyCastle"), TestCategory("Comprehensive")]
        [Timeout(120_000, CooperativeCancellation = true)]
        public void MlKem1024_10000Iterations()
        {
            CrossValidate(KyberParameter.MlKem1024, MLKemParameters.ml_kem_1024, 10_000, TestContext.CancellationTokenSource.Token);
        }
    }

    [TestClass]
    public class Quick
        : BouncyCastleCrossValidationTest
    {
        [TestMethod, TestCategory("BouncyCastle"), TestCategory("BouncyCastleQuick")]
        public void MlKem512_100Iterations()
        {
            CrossValidate(KyberParameter.MlKem512, MLKemParameters.ml_kem_512, 100);
        }

        [TestMethod, TestCategory("BouncyCastle"), TestCategory("BouncyCastleQuick")]
        public void MlKem768_100Iterations()
        {
            CrossValidate(KyberParameter.MlKem768, MLKemParameters.ml_kem_768, 100);
        }

        [TestMethod, TestCategory("BouncyCastle"), TestCategory("BouncyCastleQuick")]
        public void MlKem1024_100Iterations()
        {
            CrossValidate(KyberParameter.MlKem1024, MLKemParameters.ml_kem_1024, 100);
        }
    }
}