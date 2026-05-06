namespace KyberNET.Testing.Unit.Keys
{
    using KyberNET.Constants;
    using KyberNET.Exceptions;
    using KyberNET.Keys;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class KyberEncryptionKeyTest
    {
        [TestClass]
        public class Constructor
            : KyberEncryptionKeyTest
        {
            [TestMethod, TestCategory("Keys"), TestCategory("EncryptionKey")]
            public void ConstructsWithValidBytesForMlKem512()
            {
                // Arrange
                var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
                var nttSeed = new byte[KyberConstants.N_BYTES];

                // Act
                var key = new KyberEncryptionKey(KyberParameter.MlKem512, keyBytes, nttSeed);

                // Assert
                Assert.AreSame(KyberParameter.MlKem512, key.Parameter);
            }

            [TestMethod, TestCategory("Keys"), TestCategory("EncryptionKey")]
            public void ConstructsWithValidBytesForMlKem768()
            {
                // Arrange
                var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem768.DecryptionKeyLength);
                var nttSeed = new byte[KyberConstants.N_BYTES];

                // Act
                var key = new KyberEncryptionKey(KyberParameter.MlKem768, keyBytes, nttSeed);

                // Assert
                Assert.AreSame(KyberParameter.MlKem768, key.Parameter);
            }

            [TestMethod, TestCategory("Keys"), TestCategory("EncryptionKey")]
            public void ConstructsWithValidBytesForMlKem1024()
            {
                // Arrange
                var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem1024.DecryptionKeyLength);
                var nttSeed = new byte[KyberConstants.N_BYTES];

                // Act
                var key = new KyberEncryptionKey(KyberParameter.MlKem1024, keyBytes, nttSeed);

                // Assert
                Assert.AreSame(KyberParameter.MlKem1024, key.Parameter);
            }

            [TestMethod, TestCategory("Keys"), TestCategory("EncryptionKey")]
            public void ThrowsForInvalidCoefficients()
            {
                // Arrange
                var keyBytes = KeyTestHelpers.MakeInvalidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
                var nttSeed = new byte[KyberConstants.N_BYTES];

                // Act & Assert
                Assert.ThrowsException<InvalidKyberKeyException>(() => new KyberEncryptionKey(KyberParameter.MlKem512, keyBytes, nttSeed));
            }

            [TestMethod, TestCategory("Keys"), TestCategory("EncryptionKey")]
            public void MakesDefensiveCopy()
            {
                // Arrange
                var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
                var nttSeed = new byte[KyberConstants.N_BYTES];
                var key = new KyberEncryptionKey(KyberParameter.MlKem512, keyBytes, nttSeed);

                // Act
                keyBytes[0] = 0xFF;
                nttSeed[0] = 0xFF;

                // Assert
                Assert.AreEqual((byte)0, key.KeyBytes[0]);
                Assert.AreEqual((byte)0, key.NttSeed[0]);
            }
        }

        [TestClass]
        public class FullBytes
            : KyberEncryptionKeyTest
        {
            [TestMethod, TestCategory("Keys"), TestCategory("EncryptionKey")]
            public void HasCorrectLengthAndContent()
            {
                // Arrange
                var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
                
                var nttSeed = new byte[KyberConstants.N_BYTES];
                nttSeed[0] = 0x42;
                
                var key = new KyberEncryptionKey(KyberParameter.MlKem512, keyBytes, nttSeed);

                // Act
                var full = key.FullBytes;

                // Assert
                Assert.AreEqual(KyberParameter.MlKem512.EncapsulationKeyLength, full.Length);
                Assert.AreEqual((byte)0x42, full[keyBytes.Length]);
            }

            [TestMethod, TestCategory("Keys"), TestCategory("EncryptionKey")]
            public void ReturnsNewArrayEachTime()
            {
                // Arrange
                var keyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
                
                var nttSeed = new byte[KyberConstants.N_BYTES];
                
                var key = new KyberEncryptionKey(KyberParameter.MlKem512, keyBytes, nttSeed);

                // Act
                var a = key.FullBytes;
                var b = key.FullBytes;

                // Assert
                Assert.AreNotSame(a, b);
            }
        }

        [TestClass]
        public class FromBytes
            : KyberEncryptionKeyTest
        {
            [TestMethod, TestCategory("Keys"), TestCategory("EncryptionKey")]
            public void InfersParameterFromLength()
            {
                // Arrange
                var fullBytes = new byte[KyberParameter.MlKem768.EncapsulationKeyLength];

                // Act
                var key = KyberEncryptionKey.FromBytes(fullBytes);

                // Assert
                Assert.AreSame(KyberParameter.MlKem768, key.Parameter);
            }

            [TestMethod, TestCategory("Keys"), TestCategory("EncryptionKey")]
            public void Roundtrips()
            {
                // Arrange
                var fullBytes = new byte[KyberParameter.MlKem512.EncapsulationKeyLength];
                fullBytes[0] = 0x01;

                // Act
                var key = KyberEncryptionKey.FromBytes(fullBytes);

                // Assert
                CollectionAssert.AreEqual(fullBytes, key.FullBytes);
            }
        }
    }
}