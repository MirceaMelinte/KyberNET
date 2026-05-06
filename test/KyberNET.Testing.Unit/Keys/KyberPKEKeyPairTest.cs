namespace KyberNET.Testing.Unit.Keys
{
    using KyberNET.Constants;
    using KyberNET.Keys;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class KyberPKEKeyPairTest
    {
        [TestClass]
        public class Constructor
            : KyberPKEKeyPairTest
        {
            [TestMethod, TestCategory("Keys"), TestCategory("PKEKeyPair")]
            public void HoldsEncryptionAndDecryptionKey()
            {
                // Arrange
                var encryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);
                var nttSeed = new byte[KyberConstants.N_BYTES];
                var decryptionKeyBytes = KeyTestHelpers.MakeValidKeyBytes(KyberParameter.MlKem512.DecryptionKeyLength);

                var encryptionKey = new KyberEncryptionKey(KyberParameter.MlKem512, encryptionKeyBytes, nttSeed);
                var decryptionKey = new KyberDecryptionKey(KyberParameter.MlKem512, decryptionKeyBytes);

                // Act
                var pair = new KyberPKEKeyPair(encryptionKey, decryptionKey);

                // Assert
                Assert.AreSame(encryptionKey, pair.EncryptionKey);
                Assert.AreSame(decryptionKey, pair.DecryptionKey);
            }
        }
    }
}