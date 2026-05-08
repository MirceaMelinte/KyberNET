namespace KyberNET.Testing.Integration.Api
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using KyberNET.Api;
    using KyberNET.Constants;
    using KyberNET.Internal;
    using KyberNET.Keys;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class MlKemIntegrationTest
    {
        private static byte[] MakeSeed(byte fill)
        {
            var seed = new byte[KyberConstants.N_BYTES];
            Array.Fill(seed, fill);
            return seed;
        }

        private static KyberKEMKeyPair MakeKeyPair(KyberParameter parameter, byte randFill = 0x11, byte pkeFill = 0x22)
            => KyberKeyGenerator.Generate(parameter, MakeSeed(randFill), MakeSeed(pkeFill));

        [TestClass]
        public class Generate
            : MlKemIntegrationTest
        {
            [TestMethod, TestCategory("Integration"), TestCategory("Generate")]
            public void DeterministicWithSameSeeds()
            {
                // Arrange & Act
                var pair1 = MakeKeyPair(KyberParameter.MlKem768, 0x42, 0xAB);
                var pair2 = MakeKeyPair(KyberParameter.MlKem768, 0x42, 0xAB);

                // Assert
                CollectionAssert.AreEqual(pair1.EncapsulationKey.FullBytes, pair2.EncapsulationKey.FullBytes);
                CollectionAssert.AreEqual(pair1.DecapsulationKey.FullBytes, pair2.DecapsulationKey.FullBytes);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Generate")]
            public void DeterministicForAllParameterSets()
            {
                var parameters = new[] { KyberParameter.MlKem512, KyberParameter.MlKem768, KyberParameter.MlKem1024 };

                foreach (var param in parameters)
                {
                    // Arrange & Act
                    var pair1 = MakeKeyPair(param, 0x42, 0xAB);
                    var pair2 = MakeKeyPair(param, 0x42, 0xAB);

                    // Assert
                    CollectionAssert.AreEqual(pair1.EncapsulationKey.FullBytes, pair2.EncapsulationKey.FullBytes);
                    CollectionAssert.AreEqual(pair1.DecapsulationKey.FullBytes, pair2.DecapsulationKey.FullBytes);
                }
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Generate")]
            public void EncapsulationKeyHasCorrectLengthForAllParameterSets()
            {
                var parameters = new[] { KyberParameter.MlKem512, KyberParameter.MlKem768, KyberParameter.MlKem1024 };

                foreach (var param in parameters)
                {
                    // Act
                    var keyPair = KyberKeyGenerator.Generate(param);

                    // Assert
                    Assert.AreEqual(param.EncapsulationKeyLength, keyPair.EncapsulationKey.FullBytes.Length);
                }
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Generate")]
            public void DecapsulationKeyHasCorrectLengthForAllParameterSets()
            {
                var parameters = new[] { KyberParameter.MlKem512, KyberParameter.MlKem768, KyberParameter.MlKem1024 };

                foreach (var param in parameters)
                {
                    // Act
                    var keyPair = KyberKeyGenerator.Generate(param);

                    // Assert
                    Assert.AreEqual(param.DecapsulationKeyLength, keyPair.DecapsulationKey.FullBytes.Length);
                }
            }
        }

        [TestClass]
        public class Encapsulate
            : MlKemIntegrationTest
        {
            [TestMethod, TestCategory("Integration"), TestCategory("Encapsulate")]
            public void DeterministicWithSamePlaintext()
            {
                // Arrange
                var keyPair = MakeKeyPair(KyberParameter.MlKem768);
                var plainText1 = MakeSeed(0xCC);
                var plainText2 = MakeSeed(0xCC);

                // Act
                var result1 = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText1);
                var result2 = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText2);

                // Assert
                CollectionAssert.AreEqual(result1.SharedSecretKey, result2.SharedSecretKey);
                CollectionAssert.AreEqual(result1.CipherText.FullBytes, result2.CipherText.FullBytes);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Encapsulate")]
            public void CiphertextHasCorrectLengthForAllParameterSets()
            {
                var parameters = new[] { KyberParameter.MlKem512, KyberParameter.MlKem768, KyberParameter.MlKem1024 };

                foreach (var param in parameters)
                {
                    // Arrange
                    var keyPair = KyberKeyGenerator.Generate(param);

                    // Act
                    var result = keyPair.EncapsulationKey.Encapsulate();

                    // Assert
                    Assert.AreEqual(param.CiphertextLength, result.CipherText.FullBytes.Length);
                }
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Encapsulate")]
            public void SharedSecretIsAlways32Bytes()
            {
                var parameters = new[] { KyberParameter.MlKem512, KyberParameter.MlKem768, KyberParameter.MlKem1024 };

                foreach (var param in parameters)
                {
                    // Arrange
                    var keyPair = KyberKeyGenerator.Generate(param);

                    // Act
                    var result = keyPair.EncapsulationKey.Encapsulate();

                    // Assert
                    Assert.AreEqual(32, result.SharedSecretKey.Length);
                }
            }
        }

        [TestClass]
        public class Decapsulate
            : MlKemIntegrationTest
        {
            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void RecoversSharedSecretMlKem512()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem512);
                var result = keyPair.EncapsulationKey.Encapsulate();

                // Act
                var recoveredSecret = keyPair.DecapsulationKey.Decapsulate(result.CipherText);

                // Assert
                CollectionAssert.AreEqual(result.SharedSecretKey, recoveredSecret);
                Assert.AreEqual(32, recoveredSecret.Length);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void RecoversSharedSecretMlKem768()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                var result = keyPair.EncapsulationKey.Encapsulate();

                // Act
                var recoveredSecret = keyPair.DecapsulationKey.Decapsulate(result.CipherText);

                // Assert
                CollectionAssert.AreEqual(result.SharedSecretKey, recoveredSecret);
                Assert.AreEqual(32, recoveredSecret.Length);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void RecoversSharedSecretMlKem1024()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem1024);
                var result = keyPair.EncapsulationKey.Encapsulate();

                // Act
                var recoveredSecret = keyPair.DecapsulationKey.Decapsulate(result.CipherText);

                // Assert
                CollectionAssert.AreEqual(result.SharedSecretKey, recoveredSecret);
                Assert.AreEqual(32, recoveredSecret.Length);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void DeterministicFullRoundtrip()
            {
                // Arrange
                var keyPair1 = MakeKeyPair(KyberParameter.MlKem768, 0x11, 0x22);
                var keyPair2 = MakeKeyPair(KyberParameter.MlKem768, 0x11, 0x22);
                
                var pt1 = MakeSeed(0xDD);
                var pt2 = MakeSeed(0xDD);
                
                var result1 = KyberAgreement.Encapsulate(keyPair1.EncapsulationKey, pt1);
                var result2 = KyberAgreement.Encapsulate(keyPair2.EncapsulationKey, pt2);

                // Act
                var secret1 = keyPair1.DecapsulationKey.Decapsulate(result1.CipherText);
                var secret2 = keyPair2.DecapsulationKey.Decapsulate(result2.CipherText);

                // Assert
                CollectionAssert.AreEqual(result1.SharedSecretKey, result2.SharedSecretKey);
                CollectionAssert.AreEqual(secret1, secret2);
                CollectionAssert.AreEqual(result1.SharedSecretKey, secret1);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void MultipleRoundtripsAllSucceedWithUniqueSecrets()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                var secrets = new List<byte[]>();

                for (var i = 0; i < 10; i++)
                {
                    var result = keyPair.EncapsulationKey.Encapsulate();

                    // Act
                    var recovered = keyPair.DecapsulationKey.Decapsulate(result.CipherText);

                    // Assert
                    CollectionAssert.AreEqual(result.SharedSecretKey, recovered);
                    
                    secrets.Add(result.SharedSecretKey);
                }

                for (var i = 0; i < secrets.Count; i++)
                {
                    for (var j = i + 1; j < secrets.Count; j++)
                    {
                        Assert.IsFalse(secrets[i].SequenceEqual(secrets[j]));
                    }
                }
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void WrongKeyProducesDifferentSecret()
            {
                // Arrange
                var alice = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                var bob = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                
                var result = bob.EncapsulationKey.Encapsulate();

                // Act
                var wrongSecret = alice.DecapsulationKey.Decapsulate(result.CipherText);

                // Assert
                Assert.IsFalse(result.SharedSecretKey.SequenceEqual(wrongSecret));
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void RejectedSecretIsStill32Bytes()
            {
                // Arrange
                var alice = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                var bob = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                
                var result = bob.EncapsulationKey.Encapsulate();

                // Act
                var wrongSecret = alice.DecapsulationKey.Decapsulate(result.CipherText);

                // Assert
                Assert.AreEqual(32, wrongSecret.Length);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void RejectionIsDeterministic()
            {
                // Arrange
                var alice = MakeKeyPair(KyberParameter.MlKem768, 0x11, 0x22);
                var bob = MakeKeyPair(KyberParameter.MlKem768, 0x33, 0x44);
                
                var plainText1 = MakeSeed(0xBB);
                var plainText2 = MakeSeed(0xBB);
                
                var result1 = KyberAgreement.Encapsulate(bob.EncapsulationKey, plainText1);
                var result2 = KyberAgreement.Encapsulate(bob.EncapsulationKey, plainText2);

                // Act
                var rejected1 = alice.DecapsulationKey.Decapsulate(result1.CipherText);
                var rejected2 = alice.DecapsulationKey.Decapsulate(result2.CipherText);

                // Assert
                CollectionAssert.AreEqual(rejected1, rejected2);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void WrongKeyProducesDifferentSecretForAllParameterSets()
            {
                var parameters = new[] { KyberParameter.MlKem512, KyberParameter.MlKem768, KyberParameter.MlKem1024 };

                foreach (var param in parameters)
                {
                    // Arrange
                    var alice = KyberKeyGenerator.Generate(param);
                    var bob = KyberKeyGenerator.Generate(param);
                    
                    var result = bob.EncapsulationKey.Encapsulate();

                    // Act
                    var wrongSecret = alice.DecapsulationKey.Decapsulate(result.CipherText);

                    // Assert
                    Assert.IsFalse(result.SharedSecretKey.SequenceEqual(wrongSecret));
                }
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void CrossParameterMismatch768With512ThrowsOrRejects()
            {
                // Arrange
                var keyPair512 = KyberKeyGenerator.Generate(KyberParameter.MlKem512);
                var keyPair768 = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                
                var result768 = keyPair768.EncapsulationKey.Encapsulate();

                // Act
                var threw = false;
                byte[]? wrongSecret = null;
                
                try
                {
                    wrongSecret = keyPair512.DecapsulationKey.Decapsulate(result768.CipherText);
                }
                catch (Exception)
                {
                    threw = true;
                }

                // Assert
                Assert.IsTrue(
                    threw || !result768.SharedSecretKey.SequenceEqual(wrongSecret!),
                    "Cross-parameter decapsulation should either throw or produce a different secret");
            }

            [TestMethod, TestCategory("Integration"), TestCategory("Decapsulate")]
            public void CrossParameterMismatch512With1024ThrowsOrRejects()
            {
                // Arrange
                var keyPair1024 = KyberKeyGenerator.Generate(KyberParameter.MlKem1024);
                var keyPair512 = KyberKeyGenerator.Generate(KyberParameter.MlKem512);
                
                var result512 = keyPair512.EncapsulationKey.Encapsulate();

                // Act
                var threw = false;
                byte[]? wrongSecret = null;
                try
                {
                    wrongSecret = keyPair1024.DecapsulationKey.Decapsulate(result512.CipherText);
                }
                catch (Exception)
                {
                    threw = true;
                }

                // Assert
                Assert.IsTrue(
                    threw || !result512.SharedSecretKey.SequenceEqual(wrongSecret!),
                    "Cross-parameter decapsulation should either throw or produce a different secret");
            }
        }

        [TestClass]
        public class FromBytes
            : MlKemIntegrationTest
        {
            [TestMethod, TestCategory("Integration"), TestCategory("FromBytes")]
            public void EncapsulationKeyRoundtrips()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                var encapsulationKeyBytes = keyPair.EncapsulationKey.FullBytes;

                // Act
                var reconstructed = KyberEncapsulationKey.FromBytes(encapsulationKeyBytes);

                // Assert
                CollectionAssert.AreEqual(encapsulationKeyBytes, reconstructed.FullBytes);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("FromBytes")]
            public void DecapsulationKeyRoundtrips()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                var decapsulationKeyBytes = keyPair.DecapsulationKey.FullBytes;

                // Act
                var reconstructed = KyberDecapsulationKey.FromBytes(decapsulationKeyBytes);

                // Assert
                CollectionAssert.AreEqual(decapsulationKeyBytes, reconstructed.FullBytes);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("FromBytes")]
            public void CipherTextRoundtrips()
            {
                // Arrange
                var keyPair = KyberKeyGenerator.Generate(KyberParameter.MlKem768);
                var result = keyPair.EncapsulationKey.Encapsulate();
                var cipherTextBytes = result.CipherText.FullBytes;

                // Act
                var reconstructed = KyberCipherText.FromBytes(cipherTextBytes);

                // Assert
                CollectionAssert.AreEqual(cipherTextBytes, reconstructed.FullBytes);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("FromBytes")]
            public void ReconstructedKeyDecapsulatesCorrectly()
            {
                // Arrange
                var keyPair = MakeKeyPair(KyberParameter.MlKem768);
                var plainText = MakeSeed(0xAA);
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);
                var decapsulationKeyBytes = keyPair.DecapsulationKey.FullBytes;

                // Act
                var reconstructedDk = KyberDecapsulationKey.FromBytes(decapsulationKeyBytes);
                var recoveredSecret = reconstructedDk.Decapsulate(encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(encapsulationResult.SharedSecretKey, recoveredSecret);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("FromBytes")]
            public void ReconstructedCipherTextDecapsulatesCorrectly()
            {
                // Arrange
                var keyPair = MakeKeyPair(KyberParameter.MlKem768);
                var plainText = MakeSeed(0xBB);
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);
                var cipherTextBytes = encapsulationResult.CipherText.FullBytes;

                // Act
                var reconstructedCipherText = KyberCipherText.FromBytes(cipherTextBytes);
                var recoveredSecret = keyPair.DecapsulationKey.Decapsulate(reconstructedCipherText);

                // Assert
                CollectionAssert.AreEqual(encapsulationResult.SharedSecretKey, recoveredSecret);
            }
        }

        [TestClass]
        public class FromCipherText
            : MlKemIntegrationTest
        {
            [TestMethod, TestCategory("Integration"), TestCategory("FromCipherText")]
            public void RecoversPlaintextMlKem512()
            {
                // Arrange
                var keyPair = MakeKeyPair(KyberParameter.MlKem512);
                var plainText = MakeSeed(0xAB);
                var savedPlainText = (byte[])plainText.Clone();
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                // Act
                var recovered = KyberAgreement.FromCipherText(keyPair.DecapsulationKey.Key, encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(savedPlainText, recovered);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("FromCipherText")]
            public void RecoversPlaintextMlKem768()
            {
                // Arrange
                var keyPair = MakeKeyPair(KyberParameter.MlKem768);
                var plainText = MakeSeed(0xAB);
                var savedPlainText = (byte[])plainText.Clone();
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                // Act
                var recovered = KyberAgreement.FromCipherText(keyPair.DecapsulationKey.Key, encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(savedPlainText, recovered);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("FromCipherText")]
            public void RecoversPlaintextMlKem1024()
            {
                // Arrange
                var keyPair = MakeKeyPair(KyberParameter.MlKem1024);
                var plainText = MakeSeed(0xAB);
                var savedPlainText = (byte[])plainText.Clone();
                var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                // Act
                var recovered = KyberAgreement.FromCipherText(keyPair.DecapsulationKey.Key, encapsulationResult.CipherText);

                // Assert
                CollectionAssert.AreEqual(savedPlainText, recovered);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("FromCipherText")]
            public void RecoversDifferentPlaintexts()
            {
                // Arrange
                var keyPair = MakeKeyPair(KyberParameter.MlKem768);

                for (byte fill = 0x01; fill <= 0x05; fill++)
                {
                    var plainText = MakeSeed(fill);
                    var savedPlainText = (byte[])plainText.Clone();
                    var encapsulationResult = KyberAgreement.Encapsulate(keyPair.EncapsulationKey, plainText);

                    // Act
                    var recovered = KyberAgreement.FromCipherText(keyPair.DecapsulationKey.Key, encapsulationResult.CipherText);

                    // Assert
                    CollectionAssert.AreEqual(savedPlainText, recovered);
                }
            }
        }

        [TestClass]
        public class GenerateKeyPair
            : MlKemIntegrationTest
        {
            [TestMethod, TestCategory("Integration"), TestCategory("GenerateKeyPair")]
            public void MlKem512ProducesValidKeys()
            {
                // Act
                var keyPair = MlKem512.GenerateKeyPair();

                // Assert
                Assert.AreEqual(KyberParameter.MlKem512.EncapsulationKeyLength, keyPair.EncapsulationKey.FullBytes.Length);
                Assert.AreEqual(KyberParameter.MlKem512.DecapsulationKeyLength, keyPair.DecapsulationKey.FullBytes.Length);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("GenerateKeyPair")]
            public void MlKem768ProducesValidKeys()
            {
                // Act
                var keyPair = MlKem768.GenerateKeyPair();

                // Assert
                Assert.AreEqual(KyberParameter.MlKem768.EncapsulationKeyLength, keyPair.EncapsulationKey.FullBytes.Length);
                Assert.AreEqual(KyberParameter.MlKem768.DecapsulationKeyLength, keyPair.DecapsulationKey.FullBytes.Length);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("GenerateKeyPair")]
            public void MlKem1024ProducesValidKeys()
            {
                // Act
                var keyPair = MlKem1024.GenerateKeyPair();

                // Assert
                Assert.AreEqual(KyberParameter.MlKem1024.EncapsulationKeyLength, keyPair.EncapsulationKey.FullBytes.Length);
                Assert.AreEqual(KyberParameter.MlKem1024.DecapsulationKeyLength, keyPair.DecapsulationKey.FullBytes.Length);
            }

            [TestMethod, TestCategory("Integration"), TestCategory("GenerateKeyPair")]
            public void MlKem768FullKeyExchange()
            {
                // Arrange
                var keyPair = MlKem768.GenerateKeyPair();
                var result = keyPair.EncapsulationKey.Encapsulate();

                // Act
                var recoveredSecret = keyPair.DecapsulationKey.Decapsulate(result.CipherText);

                // Assert
                CollectionAssert.AreEqual(result.SharedSecretKey, recoveredSecret);
            }
        }
    }
}