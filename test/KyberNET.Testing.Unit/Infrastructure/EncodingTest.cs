namespace KyberNET.Testing.Unit.Infrastructure
{
    using KyberNET.Constants;
    using KyberNET.Infrastructure;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public class EncodingTest
    {
        [TestClass]
        public class Decompress
        {
            [TestMethod, TestCategory("Encoding"), TestCategory("Decompress")]
            public void DecompressesZeroToZero()
            {
                // Arrange
                var coefficients = new int[] { 0 };

                // Act
                Encoding.Decompress(coefficients, 4);

                // Assert
                Assert.AreEqual(0, coefficients[0]);
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("Decompress")]
            public void DecompressesMaxValueForBitSize()
            {
                // Arrange
                var coefficients = new int[] { 1 };

                // Act
                Encoding.Decompress(coefficients, 1);

                // Assert
                Assert.AreEqual((KyberConstants.Q + 1) >> 1, coefficients[0]);
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("Decompress")]
            public void DecompressesKnownValuesForBitSize4()
            {
                // Arrange
                var coefficients = new int[] { 0, 1, 7, 15 };
                var expected = new int[]
                {
                    (KyberConstants.Q * 0 + 8) >> 4,
                    (KyberConstants.Q * 1 + 8) >> 4,
                    (KyberConstants.Q * 7 + 8) >> 4,
                    (KyberConstants.Q * 15 + 8) >> 4
                };

                // Act
                Encoding.Decompress(coefficients, 4);

                // Assert
                for (var i = 0; i < coefficients.Length; i++)
                    Assert.AreEqual(expected[i], coefficients[i]);
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("Decompress")]
            public void MutatesArrayInPlace()
            {
                // Arrange
                var coefficients = new int[] { 5, 10 };
                var original = (int[])coefficients.Clone();

                // Act
                Encoding.Decompress(coefficients, 4);

                // Assert
                Assert.AreNotEqual(original[0], coefficients[0]);
                Assert.AreNotEqual(original[1], coefficients[1]);
            }
        }

        [TestClass]
        public class FastByteDecodeAndByteEncodeInto
        {
            [TestMethod, TestCategory("Encoding"), TestCategory("FastByteDecode")]
            public void RoundTrips12BitCoefficients()
            {
                // Arrange
                var bitSize = 12;
                var poly = new int[KyberConstants.N];
                
                for (var i = 0; i < poly.Length; i++)
                {
                    poly[i] = ModMath.ToMontgomeryForm(i % KyberConstants.Q);
                }

                var encodedLength = KyberConstants.N * bitSize / 8;
                var encoded = new byte[encodedLength];

                // Act
                Encoding.ByteEncodeInto(encoded, 0, poly, bitSize);
                var decoded = Encoding.FastByteDecode(encoded, bitSize);

                // Assert
                Assert.AreEqual(KyberConstants.N, decoded.Length);
                for (var i = 0; i < poly.Length; i++)
                {
                    var expected = ModMath.BarrettReduce(ModMath.MontgomeryReduce(poly[i]));
                    Assert.AreEqual(expected, decoded[i], $"Mismatch at index {i}");
                }
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("FastByteDecode")]
            public void RoundTrips1BitValues()
            {
                // Arrange
                var bitSize = 1;
                var poly = new int[8];
                
                for (var i = 0; i < 8; i++)
                {
                    poly[i] = ModMath.ToMontgomeryForm(i % 2);
                }

                var encoded = new byte[1]; // 8 coefficients * 1 bit = 1 byte

                // Act
                Encoding.ByteEncodeInto(encoded, 0, poly, bitSize);
                var decoded = Encoding.FastByteDecode(encoded, bitSize);

                // Assert
                Assert.AreEqual(8, decoded.Length);
                
                for (var i = 0; i < 8; i++)
                {
                    var expected = ModMath.BarrettReduce(ModMath.MontgomeryReduce(poly[i]));
                    Assert.AreEqual(expected, decoded[i], $"Mismatch at index {i}");
                }
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("FastByteDecode")]
            public void DecodesWithOffset()
            {
                // Arrange
                var bitSize = 12;
                var poly = new int[] { ModMath.ToMontgomeryForm(100), ModMath.ToMontgomeryForm(200) };
                var buffer = new byte[5]; // 2 padding + 3 data
                Encoding.ByteEncodeInto(buffer, 2, poly, bitSize);

                // Act
                var decoded = Encoding.FastByteDecode(buffer, bitSize, offset: 2, length: 3);

                // Assert
                Assert.AreEqual(2, decoded.Length);
                Assert.AreEqual(ModMath.BarrettReduce(ModMath.MontgomeryReduce(poly[0])), decoded[0]);
                Assert.AreEqual(ModMath.BarrettReduce(ModMath.MontgomeryReduce(poly[1])), decoded[1]);
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("FastByteDecode")]
            public void Decodes4BitValues()
            {
                // Arrange
                var bytes = new byte[] { 0xA3 };
                var bitSize = 4;

                // Act
                var decoded = Encoding.FastByteDecode(bytes, bitSize);

                // Assert
                Assert.AreEqual(2, decoded.Length);
                Assert.AreEqual(3, decoded[0]);  // low nibble
                Assert.AreEqual(10, decoded[1]); // high nibble
            }
        }

        [TestClass]
        public class CompressAndEncodeIntoTest
        {
            [TestMethod, TestCategory("Encoding"), TestCategory("CompressAndEncodeInto")]
            public void CompressesZeroToZero()
            {
                // Arrange
                var vector = new int[] { 0 };
                var output = new byte[1];

                // Act
                Encoding.CompressAndEncodeInto(output, 0, vector, 4);

                // Assert
                Assert.AreEqual(0, output[0] & 0x0F);
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("CompressAndEncodeInto")]
            public void CompressesKnownValueWithBitSize4()
            {
                // Arrange
                var qHalf = KyberConstants.Q_HALF;
                var montQHalf = ModMath.ToMontgomeryForm(qHalf);
                var vector = new int[2];
                vector[0] = montQHalf;
                vector[1] = 0;
                var output = new byte[1]; // 2 coefficients * 4 bits = 1 byte

                // Act
                Encoding.CompressAndEncodeInto(output, 0, vector, 4);

                // Assert
                var compressed0 = output[0] & 0x0F;
                var expected = ((16 * ModMath.MontgomeryReduce(montQHalf)) + KyberConstants.Q_HALF) / KyberConstants.Q;
                Assert.AreEqual(expected & 0x0F, compressed0);
            }
        }

        [TestClass]
        public class ExpandMuseTest
        {
            [TestMethod, TestCategory("Encoding"), TestCategory("ExpandMuse")]
            public void AllZeroBytesProducesAllZeros()
            {
                // Arrange
                var bytes = new byte[] { 0x00 };

                // Act
                var result = Encoding.ExpandMuse(bytes);

                // Assert
                Assert.AreEqual(8, result.Length);
                
                for (var i = 0; i < 8; i++)
                {
                    Assert.AreEqual(0, result[i]);
                }
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("ExpandMuse")]
            public void AllOneBitsProducesConstant()
            {
                // Arrange
                var bytes = new byte[] { 0xFF };
                var expectedValue = ModMath.ToMontgomeryForm(KyberConstants.Q_HALF + 1);

                // Act
                var result = Encoding.ExpandMuse(bytes);

                // Assert
                Assert.AreEqual(8, result.Length);
                
                for (var i = 0; i < 8; i++)
                {
                    Assert.AreEqual(expectedValue, result[i]);
                }
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("ExpandMuse")]
            public void SingleBitSetExpandsCorrectly()
            {
                // Arrange
                var bytes = new byte[] { 0x01 };
                var expectedValue = ModMath.ToMontgomeryForm(KyberConstants.Q_HALF + 1);

                // Act
                var result = Encoding.ExpandMuse(bytes);

                // Assert
                Assert.AreEqual(expectedValue, result[0]);
                
                for (var i = 1; i < 8; i++)
                {
                    Assert.AreEqual(0, result[i]);
                }
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("ExpandMuse")]
            public void OutputLengthIsEightTimesInputLength()
            {
                // Arrange
                var bytes = new byte[32];

                // Act
                var result = Encoding.ExpandMuse(bytes);

                // Assert
                Assert.AreEqual(256, result.Length);
            }
        }

        [TestClass]
        public class VectorToMontVectorTest
        {
            [TestMethod, TestCategory("Encoding"), TestCategory("VectorToMontVector")]
            public void ConvertsZeroToZero()
            {
                // Arrange
                var vector = new int[] { 0 };

                // Act
                Encoding.VectorToMontVector(vector);

                // Assert
                Assert.AreEqual(0, vector[0]);
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("VectorToMontVector")]
            public void ConvertsAndReducesInPlace()
            {
                // Arrange
                var vector = new int[] { 1, 100, KyberConstants.Q - 1 };
                var expected = new int[3];
                
                for (var i = 0; i < 3; i++)
                {
                    expected[i] = ModMath.BarrettReduce(ModMath.ToMontgomeryForm(vector[i]));
                }

                // Act
                Encoding.VectorToMontVector(vector);

                // Assert
                for (var i = 0; i < 3; i++)
                    Assert.AreEqual(expected[i], vector[i]);
            }

            [TestMethod, TestCategory("Encoding"), TestCategory("VectorToMontVector")]
            public void ResultsAreInReducedRange()
            {
                // Arrange
                var vector = new int[] { 0, 1, 1000, 3000, KyberConstants.Q - 1 };

                // Act
                Encoding.VectorToMontVector(vector);

                // Assert
                for (var i = 0; i < vector.Length; i++)
                {
                    Assert.IsTrue(vector[i] >= 0, $"Negative value at index {i}");
                    Assert.IsTrue(vector[i] <= 2 * KyberConstants.Q, $"Too large at index {i}");
                }
            }
        }

        [TestClass]
        public class MultiplyNttsWithOffset
        {
            [TestMethod, TestCategory("PolyMath"), TestCategory("MultiplyNtts")]
            public void OffsetZeroMatchesNoOffsetOverload()
            {
                // Arrange
                var ntt1 = new int[KyberConstants.N];
                var ntt2 = new int[KyberConstants.N];
                
                for (var i = 0; i < KyberConstants.N; i++)
                {
                    ntt1[i] = ModMath.ToMontgomeryForm((i * 7 + 3) % KyberConstants.Q);
                    ntt2[i] = ModMath.ToMontgomeryForm((i * 11 + 5) % KyberConstants.Q);
                }

                // Act
                var resultNoOffset = PolyMath.MultiplyNtts(ntt1, ntt2);
                var resultZeroOffset = PolyMath.MultiplyNtts(ntt1, ntt2, 0);

                // Assert
                for (var i = 0; i < KyberConstants.N; i++)
                {
                    Assert.AreEqual(resultNoOffset[i], resultZeroOffset[i], $"Mismatch at index {i}");
                }
            }

            [TestMethod, TestCategory("PolyMath"), TestCategory("MultiplyNtts")]
            public void OffsetShiftsReadsFromFirstArray()
            {
                // Arrange
                var ntt1 = new int[KyberConstants.N * 2];
                var ntt2 = new int[KyberConstants.N];
                
                for (var i = 0; i < KyberConstants.N; i++)
                {
                    ntt1[i] = ModMath.ToMontgomeryForm((i * 3) % KyberConstants.Q);
                    ntt1[i + KyberConstants.N] = ModMath.ToMontgomeryForm((i * 13 + 7) % KyberConstants.Q);
                    ntt2[i] = ModMath.ToMontgomeryForm((i * 5 + 1) % KyberConstants.Q);
                }

                // Act
                var resultWithOffset = PolyMath.MultiplyNtts(ntt1, ntt2, KyberConstants.N);

                // Build the second half as a standalone array and multiply without offset
                var ntt1SecondHalf = new int[KyberConstants.N];
                
                for (var i = 0; i < KyberConstants.N; i++)
                {
                    ntt1SecondHalf[i] = ntt1[i + KyberConstants.N];
                }
                
                var resultDirect = PolyMath.MultiplyNtts(ntt1SecondHalf, ntt2);

                // Assert
                for (var i = 0; i < KyberConstants.N; i++)
                {
                    Assert.AreEqual(resultDirect[i], resultWithOffset[i], $"Mismatch at index {i}");
                }
            }
        }
    }
}