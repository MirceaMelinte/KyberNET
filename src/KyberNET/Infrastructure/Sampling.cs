namespace KyberNET.Infrastructure
{
    using System;
    using Constants;
    using Hashing;

    internal static class Sampling
    {
        // SHAKE-256 (seed || nonce)
        public static byte[] Prf(int eta, ReadOnlySpan<byte> seed, byte nonce)
        {
            var outputLength = (KyberConstants.N >> 2) * eta;

            // build input = seed || nonce
            var input = new byte[seed.Length + 1];
            seed.CopyTo(input);
            input[^1] = nonce;

            // SHAKE256 with variable output length (XOF)
            var shake = new SHAKE256(outputLength);
            
            return shake.Digest(input);
        }

        // SHAKE-128 (seed || i || j) -> byte stream
        public sealed class Shake128Stream
        {
            private readonly HashOutputStream @out;
            private readonly byte[] buffer;
            private int position;

            public Shake128Stream(ReadOnlySpan<byte> seed, byte b1, byte b2)
            {
                // build input = seed || b1 || b2
                var input = new byte[seed.Length + 2];
                seed.CopyTo(input);
                input[^2] = b1;
                input[^1] = b2;

                // create XOF output stream
                var inStream = SHAKE128.NewInputStream();
                inStream.Write(input);
                @out = inStream.Close();

                // buffer sized to SHAKE128 rate
                buffer = new byte[KeccakParameter.SHAKE_128.BYTERATE]; // 168
                position = buffer.Length; // force fill on first Next()
            }

            public byte Next()
            {
                if (position < buffer.Length)
                {
                    return buffer[position++];
                }
                
                @out.NextBytes(buffer);
                position = 0;

                return buffer[position++];
            }
        }

        public static Shake128Stream Xof(ReadOnlySpan<byte> seed, byte b1, byte b2)
            => new(seed, b1, b2);

        // uniform sampling according to the spec
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
                    y += bits[(2 * i * eta) + eta + j].ToInt();
                }

                f[i] = ModMath.ToMontgomeryForm(x - y);
            }

            return f;
        }
    }
}