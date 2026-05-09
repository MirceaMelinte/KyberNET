namespace KyberNET.Testing.Unit.Hashing;

using System.Text;
using KyberNET.Hashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class SHAKE128Test
{
    [TestClass]
    public class Digest
        : SHAKE128Test
    {
        [TestMethod, TestCategory("SHAKE128"), TestCategory("Digest")]
        public void ReturnsEmptyInputKAT()
        {
            // Arrange
            const string expected = "7f9c2ba4e88f827d616045507605853e";

            var api = new SHAKE128(); // default OutputLength = 16

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
        : SHAKE128Test
    {
        [TestMethod, TestCategory("SHAKE128"), TestCategory("Stream")]
        public void ReturnsEmptyInputKAT()
        {
            // Arrange
            const string expected = "7f9c2ba4e88f827d616045507605853e";

            var api = new SHAKE128(); // default OutputLength = 16
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

        [TestMethod, TestCategory("SHAKE128"), TestCategory("Stream")]
        public void AllowsMoreThanDefaultBytes()
        {
            // Arrange
            var api = new SHAKE128(); // default OutputLength = 16
            var requested = api.OutputLength + 17;

            // Act
            var bytes = api.Stream().NextBytes(requested);

            // Assert
            Assert.AreEqual(requested, bytes.Length);
        }
    }

    [TestClass]
    public class NewInputStream
        : SHAKE128Test
    {
        [TestMethod, TestCategory("SHAKE128"), TestCategory("NewInputStream")]
        public void ReturnsEmptyInputKAT()
        {
            // Arrange
            const string expected = "7f9c2ba4e88f827d616045507605853e";

            var api = new SHAKE128(); // just to read OutputLength

            var input = SHAKE128.NewInputStream();

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
}