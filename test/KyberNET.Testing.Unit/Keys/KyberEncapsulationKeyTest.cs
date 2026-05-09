namespace KyberNET.Testing.Unit.Keys;

using KyberNET.Constants;
using KyberNET.Keys;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class KyberEncapsulationKeyTest
{
    [TestClass]
    public class Constructor
        : KyberEncapsulationKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("EncapsulationKey")]
        public void WrapsEncryptionKey()
        {
            // Arrange
            var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
            var nttSeed = new byte[KyberConstants.N_BYTES];
            var encryptionKey = new KyberEncryptionKey(KyberParameter.MlKem512, keyBytes, nttSeed);

            // Act
            var encapKey = new KyberEncapsulationKey(encryptionKey);

            // Assert
            CollectionAssert.AreEqual(encryptionKey.FullBytes, encapKey.FullBytes);
        }
    }

    [TestClass]
    public class FromBytes
        : KyberEncapsulationKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("EncapsulationKey")]
        public void CreatesFromEncryptionKeyBytes()
        {
            // Arrange
            var fullBytes = new byte[KyberParameter.MlKem768.EncapsulationKeyLength];

            // Act
            var encapsulationKey = KyberEncapsulationKey.FromBytes(fullBytes);

            // Assert
            Assert.AreSame(KyberParameter.MlKem768, encapsulationKey.Key.Parameter);
        }
    }
}