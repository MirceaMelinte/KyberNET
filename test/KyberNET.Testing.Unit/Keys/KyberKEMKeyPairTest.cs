namespace KyberNET.Testing.Unit.Keys;

using System.Linq;
using KyberNET.Constants;
using KyberNET.Hashing;
using KyberNET.Keys;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class KyberKEMKeyPairTest
{
    [TestClass]
    public class Constructor
        : KyberKEMKeyPairTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("KEMKeyPair")]
        public void HoldsEncapsulationAndDecapsulationKey()
        {
            // Arrange
            var param = KyberParameter.MlKem512;
            var encryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
            var nttSeed = new byte[KyberConstants.N_BYTES];
            var encryptionKey = new KyberEncryptionKey(param, encryptionKeyBytes, nttSeed);
            var hash = new SHA3_256().Digest(encryptionKey.FullBytes);
            var decryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
            var decryptionKey = new KyberDecryptionKey(param, decryptionKeyBytes);
            var randomSeed = new byte[KyberConstants.N_BYTES];

            var encapsulationKey = new KyberEncapsulationKey(encryptionKey);
            var decapsulationKey = new KyberDecapsulationKey(decryptionKey, encryptionKey, hash, randomSeed);

            // Act
            var pair = new KyberKEMKeyPair(encapsulationKey, decapsulationKey);

            // Assert
            Assert.AreSame(encapsulationKey, pair.EncapsulationKey);
            Assert.AreSame(decapsulationKey, pair.DecapsulationKey);
        }
    }

    [TestClass]
    public class Dispose
        : KyberKEMKeyPairTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("KEMKeyPair")]
        public void DisposesDecapsulationKey()
        {
            // Arrange
            var param = KyberParameter.MlKem512;
            var encryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
            var nttSeed = new byte[KyberConstants.N_BYTES];
            var encryptionKey = new KyberEncryptionKey(param, encryptionKeyBytes, nttSeed);
            var hash = new SHA3_256().Digest(encryptionKey.FullBytes);
            var decryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
            var decryptionKey = new KyberDecryptionKey(param, decryptionKeyBytes);
            var randomSeed = new byte[KyberConstants.N_BYTES];

            var encapsulationKey = new KyberEncapsulationKey(encryptionKey);
            var decapsulationKey = new KyberDecapsulationKey(decryptionKey, encryptionKey, hash, randomSeed);

            var pair = new KyberKEMKeyPair(encapsulationKey, decapsulationKey);

            // Act
            pair.Dispose();

            // Assert
            Assert.IsTrue(decapsulationKey.Hash.All(b => b == 0));
            Assert.IsTrue(decapsulationKey.RandomSeed.All(b => b == 0));
            Assert.IsTrue(decryptionKey.KeyBytes.All(b => b == 0));
        }

        [TestMethod, TestCategory("Keys"), TestCategory("KEMKeyPair")]
        public void IsSafeToCallTwice()
        {
            // Arrange
            var param = KyberParameter.MlKem512;
            var encryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
            var nttSeed = new byte[KyberConstants.N_BYTES];
            var encryptionKey = new KyberEncryptionKey(param, encryptionKeyBytes, nttSeed);
            var hash = new SHA3_256().Digest(encryptionKey.FullBytes);
            var decryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(param.DecryptionKeyLength);
            var decryptionKey = new KyberDecryptionKey(param, decryptionKeyBytes);
            var randomSeed = new byte[KyberConstants.N_BYTES];

            var encapsulationKey = new KyberEncapsulationKey(encryptionKey);
            var decapsulationKey = new KyberDecapsulationKey(decryptionKey, encryptionKey, hash, randomSeed);

            var pair = new KyberKEMKeyPair(encapsulationKey, decapsulationKey);

            // Act
            pair.Dispose();
            pair.Dispose();

            // Assert
            Assert.IsTrue(decapsulationKey.Hash.All(b => b == 0));
        }
    }
}