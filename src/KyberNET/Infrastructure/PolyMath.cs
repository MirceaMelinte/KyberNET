namespace KyberNET.Infrastructure
{
    using Constants;
    
    /// <summary>
    /// Includes pure integer polynomial helpers. In other words, math for the NTT-domain work
    /// </summary>
    public static class PolyMath
    {
        public static int[] VectorAdd(int[] v1, int[] v2)
        {
            var output = new int[v1.Length];

            for (var i = 0; i < v1.Length; i++)
            {
                output[i] = v1[i] + v2[i];
            }

            return output;
        }

        public static int[][] VectorAdd(int[][] v1, int[][] v2)
        {
            var output = new int[v1.Length][];

            for (var i = 0; i < v1.Length; i++)
            {
                output[i] = VectorAdd(v1[i], v2[i]);
            }

            return output;
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

        // Forward Number-theoretic transform in-place
        public static int[] Ntt(int[] poly)
        {
            var a = (int[])poly.Clone();
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
                            a[j + length]);

                        a[j + length] = ModMath.BarrettReduce(a[j] - t);
                        a[j] = a[j] + t; // lazy reduction
                    }

                    k++;
                }

                length >>= 1;
            }

            // finally, do a full reduction to ensure that all outputs are < Q
            for (var i = 0; i < KyberConstants.N; i++)
            {
                a[i] = ModMath.BarrettReduce(a[i]);
            }

            return a;
        }

        public static int[] InverseNtt(int[] poly)
        {
            var a = (int[])poly.Clone();
            var length = 2;
            var k = (KyberConstants.N >> 1) - 1;

            while (length <= KyberConstants.N >> 1)
            {
                for (var start = 0; start < KyberConstants.N; start += (length << 1))
                {
                    for (var j = start; j < start + length; j++)
                    {
                        var t = a[j];
                        a[j] = t + a[j + length]; // lazy reduction
                        a[j + length] = ModMath.ProductOf(
                            PrecomputedTables.Zetas.Span[k],
                            ModMath.BarrettReduce(a[j + length] - t));
                    }

                    k--;
                }

                length <<= 1;
            }

            // multiply by n^(-1) = 512 (Montgomery form) & full reduction
            for (var i = 0; i < KyberConstants.N; i++)
            {
                a[i] = ModMath.BarrettReduce(ModMath.ProductOf(a[i], 512));
            }

            return a;
        }

        // NTT Point-wise multiplication
        public static int[] MultiplyNtts(int[] ntt1, int[] ntt2)
        {
            var output = new int[KyberConstants.N];

            for (var i = 0; i < KyberConstants.N >> 1; i++)
            {
                // 4 Montgomery multiplications per pair
                var x = ModMath.ProductOf(ntt1[2 * i], ntt2[2 * i]);
                var y =  ModMath.ProductOf(ntt1[2 * i + 1], ntt2[2 * i + 1]);

                output[2 * i] = ModMath.BarrettReduce(x + ModMath.ProductOf(y, PrecomputedTables.Gammas.Span[i]));

                output[2 * i + 1] = ModMath.BarrettReduce(
                    ModMath.ProductOf(
                        ntt1[2 * i] + ntt1[2 * i + 1],
                        ntt2[2 * i] + ntt2[2 * i + 1])
                    - x - y);
            }

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
            }

            for (var i = 0; i < k; i++)
            {
                for (var j = 0; j < k; j++)
                {
                    var a = isTransposed ? j : i;
                    var b = isTransposed ? i : j;

                    var product = MultiplyNtts(matrix[a][b], vector[j]);
                    result[i] = VectorAdd(result[i], product);
                }
            }
            
            return result;
        }
    }
}