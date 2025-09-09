namespace KyberNET.Infrastructure
{
    using System;
    using System.Security.Cryptography;
    using Constants;
    
    public static class Sampling
    {
        // SHAKE-256 (seed || nonce)
        public static byte[] Prf(int eta, ReadOnlySpan<byte> seed, byte nonce)
        {
            // TODO #13: Find native cross-platform alternative
            if (!Shake256.IsSupported)
            {
                throw new NotSupportedException("SHAKE-256 is not supported on the client platform");
            }
            
            var outputLength = (KyberConstants.N >> 2) * eta;
            var output = new byte[outputLength];

            Span<byte> input = stackalloc byte[seed.Length + 1];
            seed.CopyTo(input);
            input[^1] = nonce;

            using var shake = new Shake256();
            shake.AppendData(input);
            shake.GetHashAndReset(output);

            return output;
        }
        
        // SHAKE-128 (seed || i || j)
        public sealed class Shake128Stream
        {
            private readonly Shake128 shake;
            private readonly byte[] buffer = new byte[168];
            private int position = 168;

            public Shake128Stream(ReadOnlySpan<byte> seed, byte b1, byte b2)
            {
                shake = new Shake128();
                Span<byte> first = stackalloc byte[seed.Length + 2];
                seed.CopyTo(first);
                first[^2] = b1;
                first[^1] = b2;
                shake.AppendData(first);
            }

            public byte Next()
            {
                if (position >= buffer.Length)
                {
                    shake.GetHashAndReset(buffer);
                    position = 0;
                }

                return buffer[position++];
            }
        }

        public static Shake128Stream Xof(ReadOnlySpan<byte> seed, byte b1, byte b2)
            => new Shake128Stream(seed, b1, b2);

        // Uniform sampling from the spec
        public static int[] SampleNTT(Shake128Stream stream)
        {
            var coeffs = new int[KyberConstants.N];
            Span<byte> triple = stackalloc byte[3];

            var j = 0;

            while (j < KyberConstants.N)
            {
                // pull 3 bytes -> 2x 12-bit candidates
                triple[0] = stream.Next();
                triple[1] = stream.Next();
                triple[2] = stream.Next();

                var d1 = (triple[0] | (triple[1] << 8)) & 0x0FFF;
                var d2 = ((triple[1] >> 4) | (triple[2] << 4)) & 0x0FFF;

                if (d1 < KyberConstants.Q)
                {
                    coeffs[j++] = ModMath.ToMontgomeryForm(d1);
                }

                if (j < KyberConstants.N && d2 < KyberConstants.Q)
                {
                    coeffs[j++] = ModMath.ToMontgomeryForm(d2);
                }
            }

            return coeffs;
        }

        // Centered Binomial Distribution sampler
        public static int[] SamplePolyCBD(int eta, ReadOnlySpan<byte> bytes)
        {
            var bits = BitOps.BytesToBits(bytes);
            var f = new int[KyberConstants.N];

            for (var i = 0; i < KyberConstants.N; i++)
            {
                var x = 0;
                var y = 0;

                for (var j = 0; j < eta; j++)
                {
                    x += bits[(2 * i * eta) + j].ToInt();
                    y = bits[(2 * i * eta) + eta + j].ToInt();
                }
                
                f[i] = ModMath.ToMontgomeryForm(x - y);
            }

            return f;
        }
    }
}