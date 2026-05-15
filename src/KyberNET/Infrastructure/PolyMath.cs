namespace KyberNET.Infrastructure;

using Constants;

/// <summary>
/// Includes pure integer polynomial helpers. In other words, math for the NTT-domain work
/// </summary>
internal static class PolyMath
{
    public static void VectorAdd(int[] target, int[] source)
    {
        for (var i = 0; i < target.Length; i++)
        {
            target[i] += source[i];
        }
    }

    public static void VectorAdd(int[][] target, int[][] source)
    {
        for (var i = 0; i < target.Length; i++)
        {
            VectorAdd(target[i], source[i]);
        }
    }

    public static int[] ToMontgomeryVector(int[] coefficients)
    {
        var r = new int[coefficients.Length];

        for (var i = 0; i < coefficients.Length; i++)
        {
            r[i] = ModMath.ToMontgomeryForm(coefficients[i]);
        }

        return r;
    }

    public static int[] FromMontgomeryVector(int[] coefficients)
    {
        var r = new int[coefficients.Length];

        for (var i = 0; i < coefficients.Length; i++)
        {
            r[i] = ModMath.MontgomeryReduce(coefficients[i]);
        }

        return r;
    }

    public static void Ntt(int[] poly)
    {
        var length = KyberConstants.N >> 1;
        var k = 1;

        while (length >= 2)
        {
            for (var start = 0; start < KyberConstants.N; start += (length << 1))
            {
                for (var j = start; j < start + length; j++)
                {
                    var t = ModMath.ProductOf(
                        PrecomputedTables.Zetas.Span[k],
                        poly[j + length]);

                    poly[j + length] = poly[j] - t;
                    poly[j] = poly[j] + t; // lazy reduction
                }

                k++;
            }

            length >>= 1;
        }
    }

    public static void InverseNtt(int[] poly)
    {
        var length = 2;
        var k = (KyberConstants.N >> 1) - 1;

        while (length <= KyberConstants.N >> 1)
        {
            for (var start = 0; start < KyberConstants.N; start += (length << 1))
            {
                for (var j = start; j < start + length; j++)
                {
                    var t = poly[j];
                    poly[j] = t + poly[j + length]; // lazy reduction
                    poly[j + length] = ModMath.ProductOf(
                        PrecomputedTables.Zetas.Span[k],
                        poly[j + length] - t);
                }

                k--;
            }

            length <<= 1;
        }

        for (var i = 0; i < KyberConstants.N; i++)
        {
            poly[i] = ModMath.ProductOf(poly[i], 512);
        }
    }

    // NTT Point-wise multiplication
    public static void MultiplyNttsInto(int[] output, int[] ntt1, int[] ntt2, int ntt1Offset = 0)
    {
        for (var i = 0; i < KyberConstants.N >> 1; i++)
        {
            // 4 Montgomery multiplications per pair
            var a = i << 1;
            var b = a + 1;

            var x = ModMath.ProductOf(ntt1[a + ntt1Offset], ntt2[a]);
            var y = ModMath.ProductOf(ntt1[b + ntt1Offset], ntt2[b]);

            output[a] = ModMath.ProductOf(y, PrecomputedTables.Gammas.Span[i]) + x;
            output[b] = ModMath.ProductOf(
                ntt1[a + ntt1Offset] + ntt1[b + ntt1Offset],
                ntt2[a] + ntt2[b]) - x - y;
        }
    }

    public static void MultiplyNttsAddInto(int[] output, int[] ntt1, int[] ntt2)
    {
        for (var i = 0; i < KyberConstants.N >> 1; i++)
        {
            var a = i << 1;
            var b = a + 1;

            var x = ModMath.ProductOf(ntt1[a], ntt2[a]);
            var y = ModMath.ProductOf(ntt1[b], ntt2[b]);

            output[a] += ModMath.ProductOf(y, PrecomputedTables.Gammas.Span[i]) + x;
            output[b] += ModMath.ProductOf(
                ntt1[a] + ntt1[b],
                ntt2[a] + ntt2[b]) - x - y;
        }
    }

    public static int[] MultiplyNtts(int[] ntt1, int[] ntt2)
    {
        var output = new int[KyberConstants.N];
        MultiplyNttsInto(output, ntt1, ntt2);
        
        return output;
    }

    public static int[] MultiplyNtts(int[] ntt1, int[] ntt2, int ntt1Offset)
    {
        var output = new int[KyberConstants.N];
        MultiplyNttsInto(output, ntt1, ntt2, ntt1Offset);
        
        return output;
    }

    // NTT Matrix x vector
    public static int[][] NttMatrixVectorDot(int[][][] matrix, int[][] vector, bool isTransposed = false)
    {
        var k = vector.Length;
        var result = new int[k][];

        for (var i = 0; i < k; i++)
        {
            result[i] = new int[KyberConstants.N];

            for (var j = 0; j < k; j++)
            {
                var a = isTransposed ? j : i;
                var b = isTransposed ? i : j;

                MultiplyNttsAddInto(result[i], matrix[a][b], vector[j]);
            }
        }

        return result;
    }
}