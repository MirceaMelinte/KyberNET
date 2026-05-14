namespace KyberNET.Testing.Unit.Keys;

using System.Linq;
using KyberNET.Constants;
using KyberNET.Exceptions;
using KyberNET.Hashing;
using KyberNET.Keys;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class KyberDecapsulationKeyTest
{
    private static KyberDecapsulationKey MakeValidDecapsulationKey(KyberParameter param)
    {
        var decryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
        var encryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
        var nttSeed = new byte[KyberConstants.N_BYTES];

        var decryptionKey = new KyberDecryptionKey(param, decryptionKeyBytes);
        var encryptionKey = new KyberEncryptionKey(param, encryptionKeyBytes, nttSeed);

        var hash = new SHA3_256().Digest(encryptionKey.FullBytes);
        var randomSeed = new byte[KyberConstants.N_BYTES];

        return new KyberDecapsulationKey(decryptionKey, encryptionKey, hash, randomSeed);
    }

    [TestClass]
    public class Constructor
        : KyberDecapsulationKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("DecapsulationKey")]
        public void ConstructsWithValidHashForMlKem512()
        {
            // Act
            var key = MakeValidDecapsulationKey(KyberParameter.MlKem512);

            // Assert
            Assert.AreSame(KyberParameter.MlKem512, key.Parameter);
        }

        [TestMethod, TestCategory("Keys"), TestCategory("DecapsulationKey")]
        public void ConstructsWithValidHashForMlKem768()
        {
            // Act
            var key = MakeValidDecapsulationKey(KyberParameter.MlKem768);

            // Assert
            Assert.AreSame(KyberParameter.MlKem768, key.Parameter);
        }

        [TestMethod, TestCategory("Keys"), TestCategory("DecapsulationKey")]
        public void ThrowsWhenHashDoesNotMatchEncryptionKey()
        {
            // Arrange
            var param = KyberParameter.MlKem512;
            var decryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
            var encryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
            var nttSeed = new byte[KyberConstants.N_BYTES];

            var decryptionKey = new KyberDecryptionKey(param, decryptionKeyBytes);
            var encryptionKey = new KyberEncryptionKey(param, encryptionKeyBytes, nttSeed);

            var wrongHash = new byte[KyberConstants.N_BYTES];
            wrongHash[0] = 0xFF;
            var randomSeed = new byte[KyberConstants.N_BYTES];

            // Act & Assert
            Assert.ThrowsExactly<InvalidKyberKeyException>(
                () => new KyberDecapsulationKey(decryptionKey, encryptionKey, wrongHash, randomSeed));
        }
    }

    [TestClass]
    public class FullBytes
        : KyberDecapsulationKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("DecapsulationKey")]
        public void HasCorrectLength()
        {
            // Arrange
            var key = MakeValidDecapsulationKey(KyberParameter.MlKem512);

            // Act
            var full = key.FullBytes;

            // Assert
            Assert.AreEqual(KyberParameter.MlKem512.DecapsulationKeyLength, full.Length);
        }
    }

    [TestClass]
    public class FromBytes
        : KyberDecapsulationKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("DecapsulationKey")]
        public void Roundtrips()
        {
            // Arrange
            var key = MakeValidDecapsulationKey(KyberParameter.MlKem768);
            var fullBytes = key.FullBytes;

            // Act
            var restored = KyberDecapsulationKey.FromBytes(fullBytes);

            // Assert
            CollectionAssert.AreEqual(fullBytes, restored.FullBytes);
        }

        [TestMethod, TestCategory("Keys"), TestCategory("DecapsulationKey")]
        public void ThrowsForInvalidLength()
        {
            // Act & Assert
            Assert.ThrowsExactly<UnsupportedKyberVariantException>(() => KyberDecapsulationKey.FromBytes(new byte[999]));
        }
    }

    [TestClass]
    public class Dispose
        : KyberDecapsulationKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("DecapsulationKey")]
        public void ZeroesSensitiveFields()
        {
            // Arrange
            var key = MakeValidDecapsulationKey(KyberParameter.MlKem512);

            // Act
            key.Dispose();

            // Assert
            Assert.IsTrue(key.Hash.All(b => b == 0));
            Assert.IsTrue(key.RandomSeed.All(b => b == 0));
            Assert.IsTrue(key.Key.KeyBytes.All(b => b == 0));
        }

        [TestMethod, TestCategory("Keys"), TestCategory("DecapsulationKey")]
        public void IsSafeToCallTwice()
        {
            // Arrange
            var key = MakeValidDecapsulationKey(KyberParameter.MlKem768);

            // Act
            key.Dispose();
            key.Dispose();

            // Assert
            Assert.IsTrue(key.Hash.All(b => b == 0));
        }
    }
}