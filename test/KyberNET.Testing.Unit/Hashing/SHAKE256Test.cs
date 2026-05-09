namespace KyberNET.Testing.Unit.Hashing;

using System.Text;
using KyberNET.Hashing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

public class SHAKE256Test
{
    [TestClass]
    public class Digest
        : SHAKE256Test
    {
        [TestMethod, TestCategory("SHAKE256"), TestCategory("Digest")]
        public void ReturnsEmptyInputKAT()
        {
            // Arrange
            const string expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";

            var api = new SHAKE256(); // default OutputLength = 32

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
        : SHAKE256Test
    {
        [TestMethod, TestCategory("SHAKE256"), TestCategory("Stream")]
        public void ReturnsEmptyInputKAT()
        {
            // Arrange
            const string expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";

            var api = new SHAKE256(); // default OutputLength = 32
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

        [TestMethod, TestCategory("SHAKE256"), TestCategory("Stream")]
        public void AllowsMoreThanDefaultBytes()
        {
            // Arrange
            var api = new SHAKE256(); // default OutputLength = 32
            var requested = api.OutputLength + 33;

            // Act
            var bytes = api.Stream().NextBytes(requested);

            // Assert
            Assert.AreEqual(requested, bytes.Length);
        }
    }

    [TestClass]
    public class NewInputStream
        : SHAKE256Test
    {
        [TestMethod, TestCategory("SHAKE256"), TestCategory("NewInputStream")]
        public void ReturnsEmptyInputKAT()
        {
            // Arrange
            const string expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";

            var api = new SHAKE256(); // just to read OutputLength

            var input = SHAKE256.NewInputStream();

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