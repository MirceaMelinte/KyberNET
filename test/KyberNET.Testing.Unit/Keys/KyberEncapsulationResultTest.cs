namespace KyberNET.Testing.Unit.Keys;

using System.Linq;
using KyberNET.Constants;
using KyberNET.Keys;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class KyberEncapsulationResultTest
{
    [TestClass]
    public class SharedSecretKey
        : KyberEncapsulationResultTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("EncapsulationResult")]
        public void ReturnsCopyEachTime()
        {
            // Arrange
            var secret = new byte[KyberConstants.N_BYTES];
            secret[0] = 0xAB;

            var param = KyberParameter.MlKem512;

            var coefficientSize = KyberConstants.N_BYTES * (param.Du * param.K);
            var termsSize = param.CiphertextLength - coefficientSize;

            var cipherText = new KyberCipherText(param, new byte[coefficientSize], new byte[termsSize]);
            var result = new KyberEncapsulationResult(secret, cipherText);

            // Act
            var sharedSecretKey1 = result.SharedSecretKey;
            var sharedSecretKey2 = result.SharedSecretKey;

            // Assert
            Assert.AreNotSame(sharedSecretKey1, sharedSecretKey2);
            Assert.AreEqual((byte)0xAB, sharedSecretKey1[0]);
        }
    }

    [TestClass]
    public class Constructor
        : KyberEncapsulationResultTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("EncapsulationResult")]
        public void MakesDefensiveCopyOfSecret()
        {
            // Arrange
            var secret = new byte[KyberConstants.N_BYTES];
            secret[0] = 0x01;

            var param = KyberParameter.MlKem512;

            var coefficientSize = KyberConstants.N_BYTES * (param.Du * param.K);
            var termsSize = param.CiphertextLength - coefficientSize;

            var cipherText = new KyberCipherText(param, new byte[coefficientSize], new byte[termsSize]);
            var result = new KyberEncapsulationResult(secret, cipherText);

            // Act
            secret[0] = 0xFF;

            // Assert
            Assert.AreEqual((byte)0x01, result.SharedSecretKey[0]);
        }
    }

    [TestClass]
    public class Dispose
        : KyberEncapsulationResultTest
    {
        [TestMethod, TestCategory("Keys"), TestCategory("EncapsulationResult")]
        public void ZeroesSharedSecret()
        {
            // Arrange
            var secret = new byte[KyberConstants.N_BYTES];
            secret[0] = 0xAB;

            var param = KyberParameter.MlKem512;
            var coefficientSize = KyberConstants.N_BYTES * (param.Du * param.K);
            var termsSize = param.CiphertextLength - coefficientSize;
            var cipherText = new KyberCipherText(param, new byte[coefficientSize], new byte[termsSize]);
            var result = new KyberEncapsulationResult(secret, cipherText);

            // Act
            result.Dispose();

            // Assert
            Assert.IsTrue(result.SharedSecretKey.All(b => b == 0));
        }

        [TestMethod, TestCategory("Keys"), TestCategory("EncapsulationResult")]
        public void IsSafeToCallTwice()
        {
            // Arrange
            var secret = new byte[KyberConstants.N_BYTES];
            var param = KyberParameter.MlKem512;
            var coefficientSize = KyberConstants.N_BYTES * (param.Du * param.K);
            var termsSize = param.CiphertextLength - coefficientSize;
            var cipherText = new KyberCipherText(param, new byte[coefficientSize], new byte[termsSize]);
            var result = new KyberEncapsulationResult(secret, cipherText);

            // Act
            result.Dispose();
            result.Dispose();

            // Assert
            Assert.IsTrue(result.SharedSecretKey.All(b => b == 0));
        }
    }
}