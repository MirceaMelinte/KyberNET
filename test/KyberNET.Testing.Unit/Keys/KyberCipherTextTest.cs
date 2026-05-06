namespace KyberNET.Testing.Unit.Keys
{
    using KyberNET.Constants;
    using KyberNET.Exceptions;
    using KyberNET.Keys;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class KyberCipherTextTest
    {
        [TestClass]
        public class Constructor
            : KyberCipherTextTest
        {
            [TestMethod, TestCategory("Keys"), TestCategory("CipherText")]
            public void ConstructsAndReturnsFullBytes()
            {
                // Arrange
                var param = KyberParameter.MlKem512;
                var coefficientSize = KyberConstants.N_BYTES * (param.Du * param.K);
                var termsSize = param.CiphertextLength - coefficientSize;

                var coefficients = new byte[coefficientSize];
                var terms = new byte[termsSize];
                coefficients[0] = 0xAA;
                terms[0] = 0xBB;

                // Act
                var ct = new KyberCipherText(param, coefficients, terms);
                var full = ct.FullBytes;

                // Assert
                Assert.AreEqual(param.CiphertextLength, full.Length);
                Assert.AreEqual((byte)0xAA, full[0]);
                Assert.AreEqual((byte)0xBB, full[coefficientSize]);
            }

            [TestMethod, TestCategory("Keys"), TestCategory("CipherText")]
            public void MakesDefensiveCopy()
            {
                // Arrange
                var param = KyberParameter.MlKem512;
                var coefficientSize = KyberConstants.N_BYTES * (param.Du * param.K);
                var termsSize = param.CiphertextLength - coefficientSize;

                var coefficients = new byte[coefficientSize];
                var terms = new byte[termsSize];
                var cipherText = new KyberCipherText(param, coefficients, terms);

                // Act
                coefficients[0] = 0xFF;
                terms[0] = 0xFF;

                // Assert
                Assert.AreEqual((byte)0, cipherText.EncodedCoefficients[0]);
                Assert.AreEqual((byte)0, cipherText.EncodedTerms[0]);
            }
        }

        [TestClass]
        public class FromBytesMethod
            : KyberCipherTextTest
        {
            [TestMethod, TestCategory("Keys"), TestCategory("CipherText")]
            public void InfersParameter()
            {
                // Arrange
                var bytes = new byte[KyberParameter.MlKem768.CiphertextLength];

                // Act
                var cipherText = KyberCipherText.FromBytes(bytes);

                // Assert
                Assert.AreSame(KyberParameter.MlKem768, cipherText.Parameter);
            }

            [TestMethod, TestCategory("Keys"), TestCategory("CipherText")]
            public void Roundtrips()
            {
                // Arrange
                var param = KyberParameter.MlKem1024;
                var bytes = new byte[param.CiphertextLength];
                bytes[0] = 0x12;
                bytes[^1] = 0x34;

                // Act
                var cipherText = KyberCipherText.FromBytes(bytes);

                // Assert
                CollectionAssert.AreEqual(bytes, cipherText.FullBytes);
            }

            [TestMethod, TestCategory("Keys"), TestCategory("CipherText")]
            public void ThrowsForInvalidLength()
            {
                // Act & Assert
                Assert.ThrowsException<UnsupportedKyberVariantException>(() => KyberCipherText.FromBytes(new byte[999]));
            }
        }
    }
}