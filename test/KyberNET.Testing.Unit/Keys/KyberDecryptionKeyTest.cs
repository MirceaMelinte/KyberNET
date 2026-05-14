namespace KyberNET.Testing.Unit.Keys;

using System.Linq;
using KyberNET.Constants;
using KyberNET.Exceptions;
using KyberNET.Keys;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class KyberDecryptionKeyTest
{
    [TestClass]
    public class Constructor
        : KyberDecryptionKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("DecryptionKey")]
        public void ConstructsWithValidBytesForMlKem512()
        {
            // Arrange
            var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);

            // Act
            var key = new KyberDecryptionKey(KyberParameter.MlKem512, keyBytes);

            // Assert
            Assert.AreSame(KyberParameter.MlKem512, key.Parameter);
        }

        [TestMethod, TestCategory("Keys"), TestCategory("DecryptionKey")]
        public void ThrowsForInvalidCoefficients()
        {
            // Arrange
            var keyBytes = KeyTestHelpers.MakeInvalidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);

            // Act & Assert
            Assert.ThrowsExactly<InvalidKyberKeyException>(() => new KyberDecryptionKey(KyberParameter.MlKem512, keyBytes));
        }

        [TestMethod, TestCategory("Keys"), TestCategory("DecryptionKey")]
        public void MakesDefensiveCopy()
        {
            // Arrange
            var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
            var key = new KyberDecryptionKey(KyberParameter.MlKem512, keyBytes);

            // Act
            keyBytes[0] = 0xFF;

            // Assert
            Assert.AreEqual((byte)0, key.KeyBytes[0]);
        }
    }

    [TestClass]
    public class FullBytes
        : KyberDecryptionKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("DecryptionKey")]
        public void ReturnsCopy()
        {
            // Arrange
            var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem768.DecryptionKeyLength);
            var key = new KyberDecryptionKey(KyberParameter.MlKem768, keyBytes);

            // Act
            var full = key.FullBytes;

            // Assert
            Assert.AreNotSame(key.FullBytes, full);
            CollectionAssert.AreEqual(keyBytes, full);
        }
    }

    [TestClass]
    public class FromBytes
        : KyberDecryptionKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("DecryptionKey")]
        public void InfersParameter()
        {
            // Arrange
            var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem1024.DecryptionKeyLength);

            // Act
            var key = KyberDecryptionKey.FromBytes(keyBytes);

            // Assert
            Assert.AreSame(KyberParameter.MlKem1024, key.Parameter);
        }
    }

    [TestClass]
    public class Dispose
        : KyberDecryptionKeyTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("DecryptionKey")]
        public void ZeroesKeyBytes()
        {
            // Arrange
            var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
            var key = new KyberDecryptionKey(KyberParameter.MlKem512, keyBytes);

            // Act
            key.Dispose();

            // Assert
            Assert.IsTrue(key.KeyBytes.All(b => b == 0));
        }

        [TestMethod, TestCategory("Keys"), TestCategory("DecryptionKey")]
        public void IsSafeToCallTwice()
        {
            // Arrange
            var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
            var key = new KyberDecryptionKey(KyberParameter.MlKem512, keyBytes);

            // Act
            key.Dispose();
            key.Dispose();

            // Assert
            Assert.IsTrue(key.KeyBytes.All(b => b == 0));
        }
    }
}