namespace KyberNET.Testing.Unit.Internal
{
    using System;
    using System.Linq;
    using KyberNET.Constants;
    using KyberNET.Exceptions;
    using KyberNET.Internal;
    using KyberNET.Keys;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class KyberAgreementTest
    {
        private static byte[] MakeSeed(byte fill)
        {
            var seed = new byte[KyberConstants.N_BYTES];
            Array.Fill(seed, fill);
            return seed;
        }

        private static KyberKEMKeyPair GenerateKeyPair(KyberParameter parameter, byte randFill = 0x11, byte pkeFill = 0x22)
        {
            return KyberKeyGenerator.Generate(parameter, MakeSeed(randFill), MakeSeed(pkeFill));
        }

        [TestClass]
        public class FromCipherText
            : KyberAgreementTest
        {
            [TestMethod, TestCategory("Agreement"), TestCategory("FromCipherText")]
            public void RecoversMlKem512Plaintext()
            {
                // Arrange
                var keyPair = GenerateKeyPair(KyberParameter.MlKem512);
                var plainText = MakeSeed(0xAB);
                var savedPlainText = (byte[])plainText.Clone();
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                // Act
                var recovered = KyberAgreement.FromCipherText(keyPair.DecapsulationKey.Key, encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(savedPlainText, recovered);
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("FromCipherText")]
            public void RecoversMlKem768Plaintext()
            {
                // Arrange
                var keyPair = GenerateKeyPair(KyberParameter.MlKem768);
                var plainText = MakeSeed(0xAB);
                var savedPlainText = (byte[])plainText.Clone();
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                // Act
                var recovered = KyberAgreement.FromCipherText(keyPair.DecapsulationKey.Key, encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(savedPlainText, recovered);
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("FromCipherText")]
            public void RecoversMlKem1024Plaintext()
            {
                // Arrange
                var keyPair = GenerateKeyPair(KyberParameter.MlKem1024);
                var plainText = MakeSeed(0xAB);
                var savedPlainText = (byte[])plainText.Clone();
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                // Act
                var recovered = KyberAgreement.FromCipherText(keyPair.DecapsulationKey.Key, encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(savedPlainText, recovered);
            }
        }

        [TestClass]
        public class Encapsulate
            : KyberAgreementTest
        {
            [TestMethod, TestCategory("Agreement"), TestCategory("Encapsulate")]
            public void DeterministicWithSamePlaintext()
            {
                // Arrange
                var keyPair = GenerateKeyPair(KyberParameter.MlKem768);
                var plainText1 = MakeSeed(0xAA);
                var plainText2 = MakeSeed(0xAA);

                // Act
                var result1 = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText1);
                var result2 = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText2);

                // Assert
                CollectionAssert.AreEqual(result1.SharedSecretKey, result2.SharedSecretKey);
                CollectionAssert.AreEqual(result1.CipherText.FullBytes, result2.CipherText.FullBytes);
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Encapsulate")]
            public void ThrowsOnAllZeroPlaintext()
            {
                // Arrange
                var keyPair = GenerateKeyPair(KyberParameter.MlKem768);
                var plainText = new byte[KyberConstants.N_BYTES];

                // Act & Assert
                Assert.ThrowsException<RandomBitGenerationException>(() => KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText));
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Encapsulate")]
            public void CiphertextHasCorrectLengthForAllParameterSets()
            {
                var parameters = new[] { KyberParameter.MlKem512, KyberParameter.MlKem768, KyberParameter.MlKem1024 };

                foreach (var param in parameters)
                {
                    // Arrange
                    var keyPair = GenerateKeyPair(param);
                    var plainText = MakeSeed(0xDD);

                    // Act
                    var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                    // Assert
                    Assert.AreEqual(param.CiphertextLength, encapsulationResult.CipherText.FullBytes.Length);
                }
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Encapsulate")]
            public void SharedSecretIsAlways32Bytes()
            {
                var parameters = new[] { KyberParameter.MlKem512, KyberParameter.MlKem768, KyberParameter.MlKem1024 };

                foreach (var param in parameters)
                {
                    // Arrange
                    var keyPair = GenerateKeyPair(param);
                    var plainText = MakeSeed(0xEE);

                    // Act
                    var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                    // Assert
                    Assert.AreEqual(KyberConstants.SECRET_KEY_LENGTH, encapsulationResult.SharedSecretKey.Length);
                }
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Encapsulate")]
            public void PublicApiEncapsulatesWithDefaultRng()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem768);

                // Act
                var encapsulationResult = keyPair.EncapsulationKey.Encapsulate();

                // Assert
                Assert.AreEqual(KyberConstants.SECRET_KEY_LENGTH, encapsulationResult.SharedSecretKey.Length);
                Assert.AreEqual(KyberParameter.MlKem768.CiphertextLength, encapsulationResult.CipherText.FullBytes.Length);
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Encapsulate")]
            public void PublicApiAcceptsCustomRandomProvider()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                var provider = new FixedRandomProvider(0x77);

                // Act
                var encapsulationResult = keyPair.EncapsulationKey.Encapsulate(provider);

                // Assert
                Assert.AreEqual(KyberConstants.SECRET_KEY_LENGTH, encapsulationResult.SharedSecretKey.Length);
            }
        }

        [TestClass]
        public class Decapsulate
            : KyberAgreementTest
        {
            [TestMethod, TestCategory("Agreement"), TestCategory("Decapsulate")]
            public void RecoversSharedSecretMlKem512()
            {
                // Arrange
                var keyPair = GenerateKeyPair(KyberParameter.MlKem512);
                var plainText = MakeSeed(0xBB);
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                // Act
                var sharedSecret = KyberAgreement.Decapsulate(keyPair.DecapsulationKey, encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(encapsulationResult.SharedSecretKey, sharedSecret);
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Decapsulate")]
            public void RecoversSharedSecretMlKem768()
            {
                // Arrange
                var keyPair = GenerateKeyPair(KyberParameter.MlKem768);
                var plainText = MakeSeed(0xBB);
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                // Act
                var sharedSecret = KyberAgreement.Decapsulate(keyPair.DecapsulationKey, encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(encapsulationResult.SharedSecretKey, sharedSecret);
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Decapsulate")]
            public void RecoversSharedSecretMlKem1024()
            {
                // Arrange
                var keyPair = GenerateKeyPair(KyberParameter.MlKem1024);
                var plainText = MakeSeed(0xBB);
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                // Act
                var sharedSecret = KyberAgreement.Decapsulate(keyPair.DecapsulationKey, encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(encapsulationResult.SharedSecretKey, sharedSecret);
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Decapsulate")]
            public void MultipleRoundtripsAllSucceed()
            {
                for (var i = 1; i <= 10; i++)
                {
                    // Arrange
                    var keyPair = GenerateKeyPair(KyberParameter.MlKem768, (byte)i, (byte)(i + 0x10));
                    var plainText = MakeSeed(0xBB);
                    var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                    // Act
                    var sharedSecret = KyberAgreement.Decapsulate(keyPair.DecapsulationKey, encapsulationResult.CipherText);

                    // Assert
                    CollectionAssert.AreEqual(encapsulationResult.SharedSecretKey, sharedSecret);
                }
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Decapsulate")]
            public void WrongKeyProducesImplicitRejection()
            {
                // Arrange
                var keyPairA = GenerateKeyPair(KyberParameter.MlKem768, 0x11, 0x22);
                var keyPairB = GenerateKeyPair(KyberParameter.MlKem768, 0x33, 0x44);
                
                var plainText = MakeSeed(0xBB);
                var encapsulationResult = KyberAgreement.Encapsulate(keyPairA.EncapsulationKey, plainText);

                // Act
                var rejectedSecret = KyberAgreement.Decapsulate(keyPairB.DecapsulationKey, encapsulationResult.CipherText);

                // Assert
                Assert.IsFalse(encapsulationResult.SharedSecretKey.SequenceEqual(rejectedSecret));
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Decapsulate")]
            public void ImplicitRejectionIsDeterministic()
            {
                // Arrange
                var keyPairA = GenerateKeyPair(KyberParameter.MlKem768, 0x11, 0x22);
                var keyPairB = GenerateKeyPair(KyberParameter.MlKem768, 0x33, 0x44);
                
                var pt1 = MakeSeed(0xBB);
                var pt2 = MakeSeed(0xBB);
                
                var result1 = KyberAgreement.Encapsulate(keyPairA.EncapsulationKey, pt1);
                var result2 = KyberAgreement.Encapsulate(keyPairA.EncapsulationKey, pt2);

                // Act
                var rejected1 = KyberAgreement.Decapsulate(keyPairB.DecapsulationKey, result1.CipherText);
                var rejected2 = KyberAgreement.Decapsulate(keyPairB.DecapsulationKey, result2.CipherText);

                // Assert
                CollectionAssert.AreEqual(rejected1, rejected2);
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Decapsulate")]
            public void RejectedSecretIsStill32Bytes()
            {
                // Arrange
                var keyPairA = GenerateKeyPair(KyberParameter.MlKem768, 0x11, 0x22);
                var keyPairB = GenerateKeyPair(KyberParameter.MlKem768, 0x33, 0x44);
                
                var plainText = MakeSeed(0xBB);
                var encapsulationResult = KyberAgreement.Encapsulate(keyPairA.EncapsulationKey, plainText);

                // Act
                var rejectedSecret = KyberAgreement.Decapsulate(keyPairB.DecapsulationKey, encapsulationResult.CipherText);

                // Assert
                Assert.AreEqual(KyberConstants.SECRET_KEY_LENGTH, rejectedSecret.Length);
            }

            [TestMethod, TestCategory("Agreement"), TestCategory("Decapsulate")]
            public void PublicApiRecoversSharedSecret()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                var encapsulationResult = keyPair.EncapsulationKey.Encapsulate();

                // Act
                var sharedSecret = keyPair.DecapsulationKey.Decapsulate(encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(encapsulationResult.SharedSecretKey, sharedSecret);
            }
        }

        private sealed class FixedRandomProvider(byte fill)
            : IRandomProvider
        {
            public void FillWithRandom(byte[] buffer) => Array.Fill(buffer, fill);
        }
    }
}