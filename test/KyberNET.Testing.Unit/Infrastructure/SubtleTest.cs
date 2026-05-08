namespace KyberNET.Testing.Unit.Infrastructure
{
    using KyberNET.Infrastructure;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class SubtleTest
    {
        [TestClass]
        public class Compare
            : SubtleTest
        {
            [TestMethod, TestCategory("Subtle"), TestCategory("Compare")]
            public void ReturnsZeroForEqualArrays()
            {
                // Arrange
                var a = new byte[] { 1, 2, 3, 4, 5 };
                var b = new byte[] { 1, 2, 3, 4, 5 };

                // Act
                var result = Subtle.Compare(a, b);

                // Assert
                Assert.AreEqual(0, result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("Compare")]
            public void ReturnsNonZeroForDifferentArrays()
            {
                // Arrange
                var a = new byte[] { 1, 2, 3, 4, 5 };
                var b = new byte[] { 1, 2, 99, 4, 5 };

                // Act
                var result = Subtle.Compare(a, b);

                // Assert
                Assert.AreNotEqual(0, result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("Compare")]
            public void ReturnsNonZeroForDifferentLengths()
            {
                // Arrange
                var a = new byte[] { 1, 2, 3 };
                var b = new byte[] { 1, 2, 3, 4 };

                // Act
                var result = Subtle.Compare(a, b);

                // Assert
                Assert.AreNotEqual(0, result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("Compare")]
            public void ReturnsZeroForEmptyArrays()
            {
                // Arrange
                var a = System.Array.Empty<byte>();
                var b = System.Array.Empty<byte>();

                // Act
                var result = Subtle.Compare(a, b);

                // Assert
                Assert.AreEqual(0, result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("Compare")]
            public void ReturnsNonZeroWhenDifferenceIsInLastByte()
            {
                // Arrange
                var a = new byte[] { 1, 2, 3, 4, 5 };
                var b = new byte[] { 1, 2, 3, 4, 6 };

                // Act
                var result = Subtle.Compare(a, b);

                // Assert
                Assert.AreNotEqual(0, result);
            }
        }

        [TestClass]
        public class Select
            : SubtleTest
        {
            [TestMethod, TestCategory("Subtle"), TestCategory("Select")]
            public void ReturnsFirstWhenConditionIsZero()
            {
                // Arrange
                var whenEqual = new byte[] { 10, 20, 30 };
                var whenNotEqual = new byte[] { 40, 50, 60 };

                // Act
                var result = Subtle.Select(0, whenEqual, whenNotEqual);

                // Assert
                CollectionAssert.AreEqual(whenEqual, result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("Select")]
            public void ReturnsSecondWhenConditionIsOne()
            {
                // Arrange
                var whenEqual = new byte[] { 10, 20, 30 };
                var whenNotEqual = new byte[] { 40, 50, 60 };

                // Act
                var result = Subtle.Select(1, whenEqual, whenNotEqual);

                // Assert
                CollectionAssert.AreEqual(whenNotEqual, result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("Select")]
            public void ReturnsSecondWhenConditionIsNegativeOne()
            {
                // Arrange
                var whenEqual = new byte[] { 10, 20, 30 };
                var whenNotEqual = new byte[] { 40, 50, 60 };

                // Act
                var result = Subtle.Select(-1, whenEqual, whenNotEqual);

                // Assert
                CollectionAssert.AreEqual(whenNotEqual, result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("Select")]
            public void ReturnsSecondWhenConditionIs255()
            {
                // Arrange
                var whenEqual = new byte[] { 10, 20, 30 };
                var whenNotEqual = new byte[] { 40, 50, 60 };

                // Act
                var result = Subtle.Select(255, whenEqual, whenNotEqual);

                // Assert
                CollectionAssert.AreEqual(whenNotEqual, result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("Select")]
            public void ReturnsSecondWhenConditionIsIntMinValue()
            {
                // Arrange
                var whenEqual = new byte[] { 10, 20, 30 };
                var whenNotEqual = new byte[] { 40, 50, 60 };

                // Act
                var result = Subtle.Select(int.MinValue, whenEqual, whenNotEqual);

                // Assert
                CollectionAssert.AreEqual(whenNotEqual, result);
            }
        }

        [TestClass]
        public class IsAllZero
            : SubtleTest
        {
            [TestMethod, TestCategory("Subtle"), TestCategory("IsAllZero")]
            public void ReturnsTrueForAllZeros()
            {
                // Arrange
                var data = new byte[] { 0, 0, 0, 0, 0 };

                // Act
                var result = Subtle.IsAllZero(data);

                // Assert
                Assert.IsTrue(result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("IsAllZero")]
            public void ReturnsFalseWhenFirstByteNonZero()
            {
                // Arrange
                var data = new byte[] { 1, 0, 0, 0, 0 };

                // Act
                var result = Subtle.IsAllZero(data);

                // Assert
                Assert.IsFalse(result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("IsAllZero")]
            public void ReturnsFalseWhenMiddleByteNonZero()
            {
                // Arrange
                var data = new byte[] { 0, 0, 1, 0, 0 };

                // Act
                var result = Subtle.IsAllZero(data);

                // Assert
                Assert.IsFalse(result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("IsAllZero")]
            public void ReturnsFalseWhenLastByteNonZero()
            {
                // Arrange
                var data = new byte[] { 0, 0, 0, 0, 1 };

                // Act
                var result = Subtle.IsAllZero(data);

                // Assert
                Assert.IsFalse(result);
            }

            [TestMethod, TestCategory("Subtle"), TestCategory("IsAllZero")]
            public void ReturnsTrueForEmptyArray()
            {
                // Arrange
                var data = System.Array.Empty<byte>();

                // Act
                var result = Subtle.IsAllZero(data);

                // Assert
                Assert.IsTrue(result);
            }
        }
    }
}