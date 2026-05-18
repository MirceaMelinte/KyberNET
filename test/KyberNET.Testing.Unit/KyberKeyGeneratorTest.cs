namespace KyberNET.Testing.Unit;

using KyberNET.Constants;
using KyberNET.Exceptions;
using KyberNET.Keys;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class KyberKeyGeneratorTest
{
    private static byte[] MakeSeed(byte fill)
    {
        var seed = new byte[KyberConstants.N_BYTES];
        Array.Fill(seed, fill);
        return seed;
    }

    [TestClass]
    public class PkeKeyGen
    {
        [TestMethod, TestCategory("KeyGen"), TestCategory("PkeKeyGen")]
        public void GeneratesPkeKeyPairForMlKem512()
        {
            // Arrange
            var seed = MakeSeed(0x42);

            // Act
            var pair = PkeKeyGenerator.Generate(KyberParameter.MlKem512, seed);

            // Assert
            Assert.IsNotNull(pair.EncryptionKey);
            Assert.IsNotNull(pair.DecryptionKey);
            Assert.AreEqual(KyberParameter.MlKem512.EncryptionKeyLength, pair.EncryptionKey.FullBytes.Length);
            Assert.AreEqual(KyberParameter.MlKem512.DecryptionKeyLength, pair.DecryptionKey.FullBytes.Length);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("PkeKeyGen")]
        public void GeneratesPkeKeyPairForMlKem768()
        {
            // Arrange
            var seed = MakeSeed(0x42);

            // Act
            var pair = PkeKeyGenerator.Generate(KyberParameter.MlKem768, seed);

            // Assert
            Assert.IsNotNull(pair.EncryptionKey);
            Assert.IsNotNull(pair.DecryptionKey);
            Assert.AreEqual(KyberParameter.MlKem768.EncryptionKeyLength, pair.EncryptionKey.FullBytes.Length);
            Assert.AreEqual(KyberParameter.MlKem768.DecryptionKeyLength, pair.DecryptionKey.FullBytes.Length);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("PkeKeyGen")]
        public void GeneratesPkeKeyPairForMlKem1024()
        {
            // Arrange
            var seed = MakeSeed(0x42);

            // Act
            var pair = PkeKeyGenerator.Generate(KyberParameter.MlKem1024, seed);

            // Assert
            Assert.IsNotNull(pair.EncryptionKey);
            Assert.IsNotNull(pair.DecryptionKey);
            Assert.AreEqual(KyberParameter.MlKem1024.EncryptionKeyLength, pair.EncryptionKey.FullBytes.Length);
            Assert.AreEqual(KyberParameter.MlKem1024.DecryptionKeyLength, pair.DecryptionKey.FullBytes.Length);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("PkeKeyGen")]
        public void DeterministicWithSameSeed()
        {
            // Arrange
            var seed1 = MakeSeed(0xAB);
            var seed2 = MakeSeed(0xAB);

            // Act
            var pair1 = PkeKeyGenerator.Generate(KyberParameter.MlKem768, seed1);
            var pair2 = PkeKeyGenerator.Generate(KyberParameter.MlKem768, seed2);

            // Assert
            CollectionAssert.AreEqual(pair1.EncryptionKey.FullBytes, pair2.EncryptionKey.FullBytes);
            CollectionAssert.AreEqual(pair1.DecryptionKey.FullBytes, pair2.DecryptionKey.FullBytes);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("PkeKeyGen")]
        public void DifferentSeedsProduceDifferentKeys()
        {
            // Arrange
            var seed1 = MakeSeed(0x01);
            var seed2 = MakeSeed(0x02);

            // Act
            var pair1 = PkeKeyGenerator.Generate(KyberParameter.MlKem768, seed1);
            var pair2 = PkeKeyGenerator.Generate(KyberParameter.MlKem768, seed2);

            // Assert
            Assert.IsFalse(pair1.EncryptionKey.FullBytes.SequenceEqual(pair2.EncryptionKey.FullBytes));
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("PkeKeyGen")]
        public void EncryptionKeyRoundtripsFromBytes()
        {
            // Arrange
            var seed = MakeSeed(0x55);
            var pair = PkeKeyGenerator.Generate(KyberParameter.MlKem768, seed);

            // Act
            var reconstructed = KyberEncryptionKey.FromBytes(pair.EncryptionKey.FullBytes);

            // Assert
            CollectionAssert.AreEqual(pair.EncryptionKey.FullBytes, reconstructed.FullBytes);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("PkeKeyGen")]
        public void DecryptionKeyRoundtripsFromBytes()
        {
            // Arrange
            var seed = MakeSeed(0x55);
            var pair = PkeKeyGenerator.Generate(KyberParameter.MlKem768, seed);

            // Act
            var reconstructed = KyberDecryptionKey.FromBytes(pair.DecryptionKey.FullBytes);

            // Assert
            CollectionAssert.AreEqual(pair.DecryptionKey.FullBytes, reconstructed.FullBytes);
        }
    }

    [TestClass]
    public class KemKeyGen
    {
        [TestMethod, TestCategory("KeyGen"), TestCategory("KemKeyGen")]
        public void GeneratesKemKeyPairForMlKem512()
        {
            // Arrange
            var randomSeed = MakeSeed(0x11);
            var pkeSeed = MakeSeed(0x22);

            // Act
            var pair = KyberKeyGenerator.Generate(KyberParameter.MlKem512, randomSeed, pkeSeed);

            // Assert
            Assert.IsNotNull(pair.EncapsulationKey);
            Assert.IsNotNull(pair.DecapsulationKey);
            Assert.AreEqual(KyberParameter.MlKem512.EncapsulationKeyLength, pair.EncapsulationKey.FullBytes.Length);
            Assert.AreEqual(KyberParameter.MlKem512.DecapsulationKeyLength, pair.DecapsulationKey.FullBytes.Length);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("KemKeyGen")]
        public void GeneratesKemKeyPairForMlKem768()
        {
            // Arrange
            var randomSeed = MakeSeed(0x11);
            var pkeSeed = MakeSeed(0x22);

            // Act
            var pair = KyberKeyGenerator.Generate(KyberParameter.MlKem768, randomSeed, pkeSeed);

            // Assert
            Assert.IsNotNull(pair.EncapsulationKey);
            Assert.IsNotNull(pair.DecapsulationKey);
            Assert.AreEqual(KyberParameter.MlKem768.EncapsulationKeyLength, pair.EncapsulationKey.FullBytes.Length);
            Assert.AreEqual(KyberParameter.MlKem768.DecapsulationKeyLength, pair.DecapsulationKey.FullBytes.Length);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("KemKeyGen")]
        public void GeneratesKemKeyPairForMlKem1024()
        {
            // Arrange
            var randomSeed = MakeSeed(0x11);
            var pkeSeed = MakeSeed(0x22);

            // Act
            var pair = KyberKeyGenerator.Generate(KyberParameter.MlKem1024, randomSeed, pkeSeed);

            // Assert
            Assert.IsNotNull(pair.EncapsulationKey);
            Assert.IsNotNull(pair.DecapsulationKey);
            Assert.AreEqual(KyberParameter.MlKem1024.EncapsulationKeyLength, pair.EncapsulationKey.FullBytes.Length);
            Assert.AreEqual(KyberParameter.MlKem1024.DecapsulationKeyLength, pair.DecapsulationKey.FullBytes.Length);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("KemKeyGen")]
        public void DeterministicWithSameSeeds()
        {
            // Arrange
            var rand1 = MakeSeed(0xAA);
            var pke1 = MakeSeed(0xBB);
            var rand2 = MakeSeed(0xAA);
            var pke2 = MakeSeed(0xBB);

            // Act
            var pair1 = KyberKeyGenerator.Generate(KyberParameter.MlKem768, rand1, pke1);
            var pair2 = KyberKeyGenerator.Generate(KyberParameter.MlKem768, rand2, pke2);

            // Assert
            CollectionAssert.AreEqual(pair1.EncapsulationKey.FullBytes, pair2.EncapsulationKey.FullBytes);
            CollectionAssert.AreEqual(pair1.DecapsulationKey.FullBytes, pair2.DecapsulationKey.FullBytes);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("KemKeyGen")]
        public void EncapsulationKeyRoundtripsFromBytes()
        {
            // Arrange
            var randomSeed = MakeSeed(0xCC);
            var pkeSeed = MakeSeed(0xDD);
            var pair = KyberKeyGenerator.Generate(KyberParameter.MlKem768, randomSeed, pkeSeed);

            // Act
            var reconstructed = KyberEncapsulationKey.FromBytes(pair.EncapsulationKey.FullBytes);

            // Assert
            CollectionAssert.AreEqual(pair.EncapsulationKey.FullBytes, reconstructed.FullBytes);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("KemKeyGen")]
        public void DecapsulationKeyRoundtripsFromBytes()
        {
            // Arrange
            var randomSeed = MakeSeed(0xCC);
            var pkeSeed = MakeSeed(0xDD);
            var pair = KyberKeyGenerator.Generate(KyberParameter.MlKem768, randomSeed, pkeSeed);

            // Act
            var reconstructed = KyberDecapsulationKey.FromBytes(pair.DecapsulationKey.FullBytes);

            // Assert
            CollectionAssert.AreEqual(pair.DecapsulationKey.FullBytes, reconstructed.FullBytes);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("KemKeyGen")]
        public void PublicApiGeneratesWithDefaultRng()
        {
            // Act
            var pair = KyberKeyGenerator.Generate(KyberParameter.MlKem768);

            // Assert
            Assert.IsNotNull(pair.EncapsulationKey);
            Assert.IsNotNull(pair.DecapsulationKey);
            Assert.AreEqual(KyberParameter.MlKem768.EncapsulationKeyLength, pair.EncapsulationKey.FullBytes.Length);
            Assert.AreEqual(KyberParameter.MlKem768.DecapsulationKeyLength, pair.DecapsulationKey.FullBytes.Length);
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("KemKeyGen")]
        public void PublicApiAcceptsCustomRandomProvider()
        {
            // Arrange
            var provider = new FixedRandomProvider(0x77);

            // Act
            var pair = KyberKeyGenerator.Generate(KyberParameter.MlKem768, provider);

            // Assert
            Assert.IsNotNull(pair.EncapsulationKey);
            Assert.AreEqual(KyberParameter.MlKem768.EncapsulationKeyLength, pair.EncapsulationKey.FullBytes.Length);
        }
    }

    [TestClass]
    public class AllZerosRejection
    {
        [TestMethod, TestCategory("KeyGen"), TestCategory("AllZerosRejection")]
        public void ThrowsWhenRandomSeedIsAllZeros()
        {
            // Arrange
            var randomSeed = new byte[KyberConstants.N_BYTES];
            var pkeSeed = MakeSeed(0x01);

            // Act & Assert
            Assert.ThrowsExactly<RandomBitGenerationException>(
                () => KyberKeyGenerator.Generate(KyberParameter.MlKem768, randomSeed, pkeSeed));
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("AllZerosRejection")]
        public void ThrowsWhenPkeSeedIsAllZeros()
        {
            // Arrange
            var randomSeed = MakeSeed(0x01);
            var pkeSeed = new byte[KyberConstants.N_BYTES];

            // Act & Assert
            Assert.ThrowsExactly<RandomBitGenerationException>(
                () => KyberKeyGenerator.Generate(KyberParameter.MlKem768, randomSeed, pkeSeed));
        }

        [TestMethod, TestCategory("KeyGen"), TestCategory("AllZerosRejection")]
        public void ThrowsWhenBothSeedsAreAllZeros()
        {
            // Arrange
            var randomSeed = new byte[KyberConstants.N_BYTES];
            var pkeSeed = new byte[KyberConstants.N_BYTES];

            // Act & Assert
            Assert.ThrowsExactly<RandomBitGenerationException>(
                () => KyberKeyGenerator.Generate(KyberParameter.MlKem768, randomSeed, pkeSeed));
        }
    }

    private sealed class FixedRandomProvider(byte fill)
        : IRandomProvider
    {
        public void FillWithRandom(byte[] buffer) => Array.Fill(buffer, fill);
    }
}