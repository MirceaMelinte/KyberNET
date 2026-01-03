namespace KyberNET.Testing.Unit.Hashing
{
    using System;
    using System.Text;
    using KyberNET.Hashing;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class SHA3_512Test
    {
        [TestClass]
        public class Digest
            : SHA3_512Test
        {
            [TestMethod, TestCategory("SHA3_512"), TestCategory("Digest")]
            public void ReturnsEmptyInputKAT()
            {
                // Arrange
                const string expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
                
                var api = new SHA3_512(); // default 64 bytes

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
            : SHA3_512Test
        {
            [TestMethod, TestCategory("SHA3_512"), TestCategory("Stream")]
            public void ReturnsEmptyInputKAT()
            {
                // Arrange
                const string expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
                
                var api = new SHA3_512();
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
            : SHA3_512Test
        {
            [TestMethod, TestCategory("SHA3_512"), TestCategory("NewInputStream")]
            public void ReturnsEmptyInputKAT()
            {
                // Arrange
                const string expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
                
                var api = new SHA3_512();
                
                var input = SHA3_512.NewInputStream();

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
            : SHA3_512Test
        {
            [TestMethod, TestCategory("SHA3_512"), TestCategory("NextByte")]
            public void ThrowsAfterFixedLengthUnextendable()
            {
                // Arrange
                var api = new SHA3_512();
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