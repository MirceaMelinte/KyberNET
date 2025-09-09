namespace KyberNET.Testing.Unit.Infrastructure
{
    using KyberNET.Infrastructure;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class BitOpsTest
    {
        [TestClass]
        public class BitsToBytes
        {
            [TestMethod, TestCategory("BitOps"), TestCategory("BitsToBytes")]
            public void ReturnsByteArrayOnBoolArrayInput()
            {
                // Arrange
                var bits = new[]
                {
                    true, false, true, false, true, false, true, false, // 0b01010101 => 85
                    false, true, false, true, false, true, false, true  // 0b10101010 => 170
                };
                
                // Act
                var result = BitOps.BitsToBytes(bits);

                // Assert
                Assert.AreEqual(2, result.Length);
                Assert.AreEqual(85, result[0]);
                Assert.AreEqual(170, result[1]);
            }
        }

        [TestClass]
        public class BytesToBits
        {
            [TestMethod, TestCategory("BitOps"), TestCategory("BytesToBits")]
            public void ReturnsBoolArrayOnByteArrayInput()
            {
                // Arrange
                var bytes = new byte[] { 85, 170 }; // 0b01010101, 0b10101010

                var expected = new[]
                {
                    true, false, true, false, true, false, true, false,
                    false, true, false, true, false, true, false, true
                };
                
                // Act
                var result = BitOps.BytesToBits(bytes);
                
                // Assert
                Assert.AreEqual(16, result.Length);
                CollectionAssert.AreEqual(expected, result);
            }
        }

        [TestClass]
        public class ToInt
        {
            [TestMethod, TestCategory("BitOps"), TestCategory("ToInt")]
            public void ReturnsZeroWhenBoolIsFalse()
            {
                // Arrange
                var input = false;

                // Act
                var result = input.ToInt();

                // Assert
                Assert.AreEqual(0, result);
            }

            [TestMethod, TestCategory("BitOps"), TestCategory("ToInt")]
            public void ReturnsOneWhenBoolIsTrue()
            {
                // Arrange
                var input = true;
                
                // Act
                var result = input.ToInt();
                
                // Assert
                Assert.AreEqual(1, result);
            }
        }
    }
}