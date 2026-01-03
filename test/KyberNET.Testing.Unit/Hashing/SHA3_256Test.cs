namespace KyberNET.Testing.Unit.Hashing
{
    using System;
    using System.Text;
    using KyberNET.Hashing;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class SHA3_256Test
    {
        [TestClass]
        public class Digest
            : SHA3_256Test
        {
            [TestMethod, TestCategory("SHA3_256"), TestCategory("Digest")]
            public void ReturnsEmptyInputKAT()
            {
                // Arrange
                const string expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
                
                var api = new SHA3_256(); // default 32 bytes

                // Act
                var result = api.Digest();
                var sb = new StringBuilder(result.Length * 2);
                
                foreach (var b in result)
                {
                    sb.Append(b.ToString("x2"));
                }
                
                var actual = sb.ToString();

                // Assert
                Assert.AreEqual(expected, actual);
            }
        }

        [TestClass]
        public class Stream
            : SHA3_256Test
        {
            [TestMethod, TestCategory("SHA3_256"), TestCategory("Stream")]
            public void ReturnsEmptyInputKAT()
            {
                // Arrange
                const string expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
                
                var api = new SHA3_256();
                var length = api.OutputLength;

                // Act
                var bytes = api.Stream().NextBytes(length);
                var sb = new StringBuilder(bytes.Length * 2);

                foreach (var b in bytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                
                var actual = sb.ToString();

                // Assert
                Assert.AreEqual(expected, actual);
            }
        }

        [TestClass]
        public class NewInputStream
            : SHA3_256Test
        {
            [TestMethod, TestCategory("SHA3_256"), TestCategory("NewInputStream")]
            public void ReturnsEmptyInputKAT()
            {
                // Arrange
                const string expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
                
                var api = new SHA3_256();
                HashInputStream input = SHA3_256.NewInputStream();

                // Act
                var bytes = input.Close().NextBytes(api.OutputLength);
                var sb = new StringBuilder(bytes.Length * 2);

                foreach (var b in bytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                
                var actual = sb.ToString();

                // Assert
                Assert.AreEqual(expected, actual);
            }
        }

        [TestClass]
        public class NextByte
            : SHA3_256Test
        {
            [TestMethod, TestCategory("SHA3_256"), TestCategory("NextByte")]
            public void ThrowsAfterFixedLengthUnextendable()
            {
                // Arrange
                var api = new SHA3_256();
                var len = api.OutputLength;
                var stream = api.Stream();

                // Act
                var bytes = stream.NextBytes(len);

                // Assert
                Assert.AreEqual(len, bytes.Length);
                Assert.ThrowsExactly<InvalidOperationException>(() => _ = stream.NextByte());
            }
        }
    }
}