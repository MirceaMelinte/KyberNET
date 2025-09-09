namespace KyberNET.Testing.Unit.Infrastructure
{
    using KyberNET.Constants;
    using KyberNET.Infrastructure;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class ModMathTest
    {
        [TestClass]
        public class BarrettReduce
        {
            [TestMethod, TestCategory("ModMath"), TestCategory("BarrettReduce")]
            public void ReturnsZeroWhenInputZero()
            {
                // Arrange
                var n = 0;

                // Act
                var result = ModMath.BarrettReduce(n);

                // Assert
                Assert.AreEqual(0, result);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("BarrettReduce")]
            public void ReturnsZeroWhenInputQ()
            {
                // Arrange
                var n = KyberConstants.Q;

                // Act
                var result = ModMath.BarrettReduce(n);

                // Assert
                Assert.AreEqual(0, result);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("BarrettReduce")]
            public void ReturnsPositiveWhenInputNegative()
            {
                // Arrange
                var n = -KyberConstants.Q + 17;
                var expectedMod = ((n % KyberConstants.Q)  + KyberConstants.Q) % KyberConstants.Q;
                
                // Act
                var result = ModMath.BarrettReduce(n);
                
                // Assert
                Assert.IsTrue(result >= 0);
                Assert.IsTrue(result < 2 * KyberConstants.Q);
                Assert.AreEqual(expectedMod, result % KyberConstants.Q);
            }
            
            [TestMethod, TestCategory("ModMath"), TestCategory("BarrettReduce")]
            public void ReturnsSameValueWhenNAlreadyReduced()
            {
                // Arrange
                var n = KyberConstants.Q - 42;

                // Act
                var result = ModMath.BarrettReduce(n);

                // Assert
                Assert.AreEqual(n, result);
                Assert.IsTrue(result >= 0);
                Assert.IsTrue(result < 2 * KyberConstants.Q);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("BarrettReduce")]
            public void ReturnsValueInRangeWhenLargeN()
            {
                // Arrange
                var n = 7 * KyberConstants.Q + 123;
                
                // Act
                var result = ModMath.BarrettReduce(n);
                
                // Assert
                Assert.IsTrue(result >= 0);
                Assert.IsTrue(result < 2 * KyberConstants.Q);
                Assert.AreEqual(n % KyberConstants.Q, result % KyberConstants.Q);
            }
        }

        [TestClass]
        public class MontgomeryReduce
        {
            [TestMethod, TestCategory("ModMath"), TestCategory("MontgomeryReduce")]
            public void ReturnsZeroWhenInputZero()
            {
                // Arrange
                var t = 0;

                // Act
                var result = ModMath.MontgomeryReduce(t);

                // Assert
                Assert.AreEqual(0, result);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("MontgomeryReduce")]
            public void ReturnsQWhenTEqualsQTimesRadix()
            {
                // Arrange
                var radix = 1 << 16;
                var t = KyberConstants.Q * radix;

                // Act
                var result = ModMath.MontgomeryReduce(t);

                // Assert
                Assert.AreEqual(KyberConstants.Q, result);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("MontgomeryReduce")]
            public void ReturnsValidValueNearIntUpperBoundary()
            {
                // Arrange
                var radix = 1 << 16;
                var t = KyberConstants.Q * radix - 1; // highest valid t (218 169 343)

                // Act
                var result = ModMath.MontgomeryReduce(t);

                // Assert
                Assert.IsTrue(result >= 0);
                Assert.IsTrue(result < 2 * KyberConstants.Q);
                Assert.AreEqual(t % KyberConstants.Q, ((long)result * radix) % KyberConstants.Q);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("MontgomeryReduce")]
            public void ReturnsValueInRangeWhenLargeInput()
            {
                // Arrange
                var t = (KyberConstants.Q * 12345) + 6789;
                var radix = 1 << 16;

                // Act
                var result = ModMath.MontgomeryReduce(t);

                // Assert
                Assert.IsTrue(result >= 0);
                Assert.IsTrue(result < 2 * KyberConstants.Q);
                
                // result * radix must be congruent (t mod Q)
                var lhs = (int)(((long)result * radix) % KyberConstants.Q);
                var rhs = t % KyberConstants.Q;
                
                Assert.AreEqual(lhs, rhs);
            }
        }

        [TestClass]
        public class ToMontgomeryForm
        {
            [TestMethod, TestCategory("ModMath"), TestCategory("ToMontgomeryForm")]
            public void ReturnsZeroWhenInputZero()
            {
                // Arrange
                var a = 0;

                // Act
                var result = ModMath.ToMontgomeryForm(a);

                // Assert
                Assert.AreEqual(0, result);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("ToMontgomeryForm")]
            public void ReturnsExpectedMontgomeryEquivalentForUnity()
            {
                // Arrange
                var a = 1;
                var expected = (int)(((long)a << 16) % KyberConstants.Q); // (a * R) mod Q, where R = 2^16

                // Act
                var result = ModMath.ToMontgomeryForm(a);

                // Assert
                Assert.AreEqual(expected, result);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("ToMontgomeryForm")]
            public void ReturnsSameValueWhenMultiplyByMontgomeryOne()
            {
                // Arrange
                var a = 4321;
                var montA = ModMath.ToMontgomeryForm(a);
                var oneMont = ModMath.ToMontgomeryForm(1);

                // Act
                var result = ModMath.ProductOf(montA, oneMont);

                // Assert
                Assert.AreEqual(montA, result);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("ToMontgomeryForm")]
            public void ReturnsSameValueNotOrderSensitive()
            {
                // Arrange
                var a = 1111;
                var b = 2222;
                var ma = ModMath.ToMontgomeryForm(a);
                var mb = ModMath.ToMontgomeryForm(b);

                // Act
                var ab = ModMath.ProductOf(ma, mb);
                var ba = ModMath.ProductOf(mb, ma);

                // Assert
                Assert.AreEqual(ab, ba);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("ToMontgomeryForm")]
            public void ReturnsSameValueWhenMultipliedByMontgomeryOne()
            {
                // Arrange
                var x = 987;
                var mx = ModMath.ToMontgomeryForm(x);
                var oneMont = ModMath.ToMontgomeryForm(1);

                // Act
                var result = ModMath.ProductOf(mx, oneMont);

                // Assert
                Assert.AreEqual(mx, result);
            }
        }

        [TestClass]
        public class ProductOf
        {
            [TestMethod, TestCategory("ModMath"), TestCategory("ProductOf")]
            public void ReturnsZeroWhenOneInputZero()
            {
                // Arrange
                var a = 0;
                var b = 1234;

                // Act
                var result = ModMath.ProductOf(a, b);

                // Assert
                Assert.AreEqual(0, result);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("ProductOf")]
            public void ReturnsMontgomeryProductWhenInputsInMontgomeryForm()
            {
                // Arrange
                var x = 1234;
                var y = 567;

                var mx = ModMath.ToMontgomeryForm(x);
                var my = ModMath.ToMontgomeryForm(y);

                var expected = ModMath.ToMontgomeryForm((int)(((long)x * y) % KyberConstants.Q));

                // Act
                var result = ModMath.ProductOf(mx, my);

                // Assert
                Assert.AreEqual(expected, result);
            }
        }

        [TestClass]
        public class IsModuloOfQ
        {
            [TestMethod, TestCategory("ModMath"), TestCategory("IsModuloOfQ")]
            public void ReturnsTrueWhenNLessThanQ()
            {
                // Arrange
                var n = KyberConstants.Q - 1;

                // Act
                var result = ModMath.IsModuloOfQ(n);

                // Assert
                Assert.IsTrue(result);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("IsModuloOfQ")]
            public void ReturnsFalseWhenNGreaterThanQ()
            {
                // Arrange
                var n = KyberConstants.Q + 1;

                // Act
                var resultEqual = ModMath.IsModuloOfQ(KyberConstants.Q);
                var resultGreater = ModMath.IsModuloOfQ(n);

                // Assert
                Assert.IsFalse(resultEqual);
                Assert.IsFalse(resultGreater);
            }

            [TestMethod, TestCategory("ModMath"), TestCategory("IsModuloOfQ")]
            public void ReturnsFalseWhenNNegative()
            {
                // Arrange & Act
                var resultMinusOne = ModMath.IsModuloOfQ(-1);
                var resultNegativeQ = ModMath.IsModuloOfQ(-KyberConstants.Q);

                // Assert
                Assert.IsFalse(resultMinusOne);
                Assert.IsFalse(resultNegativeQ);
            }
        }
    }
}