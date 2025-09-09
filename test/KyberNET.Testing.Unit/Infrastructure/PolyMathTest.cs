namespace KyberNET.Testing.Unit.Infrastructure
{
    using System;
    using KyberNET.Constants;
    using KyberNET.Infrastructure;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    
    public class PolyMathTest
    {
        [TestClass]
        public class VectorAdd
        {
            [TestMethod, TestCategory("PolyMath"), TestCategory("VectorAdd")]
            public void ReturnsCorrectSumWhenVectorsOfSameLength()
            {
                // Arrange
                var v1 = new[] { 1, 2, 3 };
                var v2 = new[] { 4, 5, 6 };
                var expected = new[] { 5, 7, 9 };

                // Act
                var result = PolyMath.VectorAdd(v1, v2);

                // Assert
                CollectionAssert.AreEqual(expected, result);
            }

            [TestMethod, TestCategory("PolyMath"), TestCategory("VectorAdd")]
            public void ThrowsIndexOutOfRangeWhenSecondArrayShorter()
            {
                // Arrange
                var v1 = new[] { 1, 2, 3 };
                var v2 = new[] { 4, 5 };
                
                // Act & Assert
                Assert.ThrowsExactly<IndexOutOfRangeException>(() => _ = PolyMath.VectorAdd(v1, v2));
            }

            [TestMethod, TestCategory("PolyMath"), TestCategory("VectorAdd")]
            public void ReturnsCorrectSumWhenMatricesOfSameDimensions()
            {
                // Arrange
                var m1 = new[]
                {
                    new[] { 1, 2 },
                    new[] { 3, 4 }
                };


                var m2 = new[]
                {
                    new[] { 5, 6 },
                    new[] { 7, 8 }
                };


                var expected = new[]
                {
                    new[] { 6, 8 },
                    new[] { 10, 12 }
                };
                
                // Act
                var result = PolyMath.VectorAdd(m1, m2);
                
                // Assert
                for (var i = 0; i < expected.Length; i++)
                {
                    CollectionAssert.AreEqual(expected[i], result[i]);
                }
            }

            [TestMethod, TestCategory("PolyMath"), TestCategory("VectorAdd")]
            public void ThrowsIndexOutOfRangeWhenSecondMatrixRowShorter()
            {
                // Arrange
                var m1 = new[] { new[] { 1, 2 } };
                var m2 = new[] { new[] { 3 } };
                
                // Act & Assert
                Assert.ThrowsExactly<IndexOutOfRangeException>(() => _ = PolyMath.VectorAdd(m1, m2));
            }
        }

        [TestClass]
        public class ToMontgomeryVector
        {
            [TestMethod, TestCategory("PolyMath"), TestCategory("ToMontgomeryVector")]
            public void ReturnsValuesInMontgomeryForm()
            {
                // Arrange
                var coeffs = new[] { 0, 1, 2, 3 };

                // Act
                var result = PolyMath.ToMontgomeryVector(coeffs);

                // Assert
                for (var i = 0; i < coeffs.Length; i++)
                {
                    var expected = ModMath.ToMontgomeryForm(coeffs[i]);
                    Assert.AreEqual(expected, result[i]);
                }
            }
        }

        [TestClass]
        public class FromMontgomeryVector
        {
            [TestMethod, TestCategory("PolyMath"), TestCategory("FromMontgomeryVector")]
            public void ReturnsValuesReducedFromMontgomeryForm()
            {
                // Arrange
                var coeffs = new[] { 0, 1, 2, 3 };
                
                // Act
                var result = PolyMath.FromMontgomeryVector(coeffs);
                
                // Assert
                for (var i = 0; i < coeffs.Length; i++)
                {
                    var expected = ModMath.MontgomeryReduce(coeffs[i]);
                    Assert.AreEqual(expected, result[i]);
                }
            }
        }

        [TestClass]
        public class Ntt
        {
            [TestMethod, TestCategory("PolyMath"), TestCategory("Ntt")]
            public void ReturnsZeroVectorWhenInputZeroVector()
            {
                // Arrange
                var zeroVector = new int[KyberConstants.N];

                // Act
                var result = PolyMath.Ntt(zeroVector);

                // Assert
                CollectionAssert.AreEqual(zeroVector, result);
            }
        }

        [TestClass]
        public class InverseNtt
        {
            [TestMethod, TestCategory("PolyMath"), TestCategory("InverseNtt")]
            public void ReturnsZeroVectorWhenInputZeroVector()
            {
                // Arrange
                var zeroVector = new int[KyberConstants.N];
                
                // Act
                var result = PolyMath.InverseNtt(zeroVector);
                
                // Assert
                CollectionAssert.AreEqual(zeroVector, result);
            }
        }

        [TestClass]
        public class MultiplyNtts
        {
            [TestMethod, TestCategory("PolyMath"), TestCategory("MultiplyNtts")]
            public void ReturnsZeroVectorWhenOneInputZeroVector()
            {
                // Arrange
                var zeroVector = new int[KyberConstants.N];
                var someVector = new int[KyberConstants.N];
                someVector[0] = 1;
                
                // Act
                var result1 = PolyMath.MultiplyNtts(zeroVector, someVector);
                var result2 = PolyMath.MultiplyNtts(someVector, zeroVector);

                // Assert
                CollectionAssert.AreEqual(zeroVector, result1);
                CollectionAssert.AreEqual(zeroVector, result2);
            }
        }

        [TestClass]
        public class NttMatrixVectorDot
        {
            [TestMethod, TestCategory("PolyMath"), TestCategory("NttMatrixVectorDot")]
            public void ReturnsZeroMatrixWhenMatrixAndVectorZero()
            {
                // Arrange
                var k = 3;
                var zeroVector = new int[KyberConstants.N];

                var matrix = new int[k][][];
                var vector = new int[k][];

                for (var i = 0; i < k; i++)
                {
                    matrix[i] = new int[k][];

                    for (var j = 0; j < k; j++)
                    {
                        matrix[i][j] = new int[KyberConstants.N];
                    }
                    
                    vector[i] = new int[KyberConstants.N];
                }

                var expected = new int[k][];

                for (var i = 0; i < k; i++)
                {
                    expected[i] = new int[KyberConstants.N];
                }

                // Act
                var result = PolyMath.NttMatrixVectorDot(matrix, vector);

                // Assert
                for (var i = 0; i < k; i++)
                {
                    CollectionAssert.AreEqual(expected[i], result[i]);
                }
            }
        }
    }
}