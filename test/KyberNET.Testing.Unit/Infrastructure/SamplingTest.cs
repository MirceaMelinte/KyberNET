namespace KyberNET.Testing.Unit.Infrastructure;

using KyberNET.Hashing;
using KyberNET.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class SamplingTest
{
    [TestClass]
    public class Prf
        : SamplingTest
    {
        [TestMethod, TestCategory("Sampling"), TestCategory("Prf")]
        public void ReturnsExpectedLengthAndIsDeterministicPrf()
        {
            // Arrange
            var seed = new byte[32];

            for (var i = 0; i < seed.Length; i++)
            {
                seed[i] = (byte)i;
            }

            var eta = 3;
            var nonce = (byte)7;

            // Act
            var a = Sampling.Prf(eta, seed, nonce);
            var b = Sampling.Prf(eta, seed, nonce);

            // Assert
            Assert.AreEqual((256 >> 2) * eta, a.Length);
            CollectionAssert.AreEqual(a, b);
        }
    }

    [TestClass]
    public class Xof
        : SamplingTest
    {
        [TestMethod, TestCategory("Sampling"), TestCategory("Xof")]
        public void XofStreamMatchesShake128DigestForLongOutputs()
        {
            // Arrange
            var seed = new byte[32];

            for (var i = 0; i < seed.Length; i++)
            {
                seed[i] = (byte)(255 - i);
            }

            byte b1 = 1;
            byte b2 = 2;

            // expected = SHAKE128(seed||b1||b2) for 1000 bytes
            var input = new byte[seed.Length + 2];
            seed.CopyTo(input, 0);
            input[^2] = b1;
            input[^1] = b2;

            var expected = new SHAKE128(1000).Digest(input);

            // Act
            var stream = Sampling.Xof(seed, b1, b2);

            var actual = new byte[1000];

            for (var i = 0; i < actual.Length; i++)
            {
                actual[i] = stream.Next();
            }

            // Assert
            CollectionAssert.AreEqual(expected, actual);
        }
    }
}