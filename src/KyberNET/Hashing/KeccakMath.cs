namespace KyberNET.Hashing
{
    using System;

    internal static class KeccakMath
    {
        /// <summary>
        /// Direct padding for the last absorbing block
        /// </summary>
        public static void Pad10n1Direct(byte[] bytes, int offset, FlexiByte suffix)
        {
            // set first padding byte (suffix + 01 after its bitIndex)
            bytes[offset] = (byte)(suffix.ToByte() | (1 << (suffix.BitIndex + 1)));
            
            // set most significant bit of the last byte
            bytes[^1] = (byte)(bytes[^1] | 0x80);
        }

        /// <summary>
        /// Convert SplitByteArray segment (up to 'except' bytes) into lanes
        /// </summary>
        public static long GetLongAt(SplitByteArray source, int x, int y, int except)
        {
            var offset = ((x + (5 * y)) << 3);
            if (offset + 7 > except) return 0L;

            return
                (long)(source[offset] & 0xFF) |
                ((long)(source[offset + 1] & 0xFF) << 8) |
                ((long)(source[offset + 2] & 0xFF) << 16) |
                ((long)(source[offset + 3] & 0xFF) << 24) |
                ((long)(source[offset + 4] & 0xFF) << 32) |
                ((long)(source[offset + 5] & 0xFF) << 40) |
                ((long)(source[offset + 6] & 0xFF) << 48) |
                ((long)source[offset + 7] << 56);
        }

        /// <summary>
        /// Write lanes into bytes (little-endian), whole 200B view
        /// </summary>
        public static void DirectMatrixToBytes(long[][] matrix, SplitByteArray destination)
        {
            for (var x = 0; x < 5; x++)
            {
                for (var y = 0; y < 5; y++)
                {
                    DirectLongToBytes(matrix[x][y], destination, ((x + (5 * y)) << 3));
                }
            }
        }

        /// <summary>
        /// 24-round Keccak-f[1600] permutation, in-place, optimized structure
        /// </summary>
        public static void DirectPermute(long[][] state)
        {
            for (var i = 0; i < 24; i++)
            {
                var c0 = state[0][0] ^ state[0][1] ^ state[0][2] ^ state[0][3] ^ state[0][4];
                var c1 = state[1][0] ^ state[1][1] ^ state[1][2] ^ state[1][3] ^ state[1][4];
                var c2 = state[2][0] ^ state[2][1] ^ state[2][2] ^ state[2][3] ^ state[2][4];
                var c3 = state[3][0] ^ state[3][1] ^ state[3][2] ^ state[3][3] ^ state[3][4];
                var c4 = state[4][0] ^ state[4][1] ^ state[4][2] ^ state[4][3] ^ state[4][4];

                var d0 = c4 ^ RotL(c1, 1);
                var d1 = c0 ^ RotL(c2, 1);
                var d2 = c1 ^ RotL(c3, 1);
                var d3 = c2 ^ RotL(c4, 1);
                var d4 = c3 ^ RotL(c0, 1);

                var n0 = new[]
                {
                    (state[0][0] ^ d0),
                    RotL(state[3][0] ^ d3, 28),
                    RotL(state[1][0] ^ d1, 1),
                    RotL(state[4][0] ^ d4, 27),
                    RotL(state[2][0] ^ d2, 62)
                };
                
                var n1 = new[]
                {
                    RotL(state[1][1] ^ d1, 44),
                    RotL(state[4][1] ^ d4, 20),
                    RotL(state[2][1] ^ d2, 6),
                    RotL(state[0][1] ^ d0, 36),
                    RotL(state[3][1] ^ d3, 55)
                };
                
                var n2 = new[]
                {
                    RotL(state[2][2] ^ d2, 43),
                    RotL(state[0][2] ^ d0, 3),
                    RotL(state[3][2] ^ d3, 25),
                    RotL(state[1][2] ^ d1, 10),
                    RotL(state[4][2] ^ d4, 39)
                };
                
                var n3 = new[]
                {
                    RotL(state[3][3] ^ d3, 21),
                    RotL(state[1][3] ^ d1, 45),
                    RotL(state[4][3] ^ d4, 8),
                    RotL(state[2][3] ^ d2, 15),
                    RotL(state[0][3] ^ d0, 41)
                };
                
                var n4 = new[]
                {
                    RotL(state[4][4] ^ d4, 14),
                    RotL(state[2][4] ^ d2, 61),
                    RotL(state[0][4] ^ d0, 18),
                    RotL(state[3][4] ^ d3, 56),
                    RotL(state[1][4] ^ d1, 2)
                };

                state[0][0] = n0[0] ^ (~n1[0] & n2[0]) ^ KeccakConstants.ROUND[i];
                state[0][1] = n0[1] ^ (~n1[1] & n2[1]);
                state[0][2] = n0[2] ^ (~n1[2] & n2[2]);
                state[0][3] = n0[3] ^ (~n1[3] & n2[3]);
                state[0][4] = n0[4] ^ (~n1[4] & n2[4]);

                state[1][0] = n1[0] ^ (~n2[0] & n3[0]);
                state[1][1] = n1[1] ^ (~n2[1] & n3[1]);
                state[1][2] = n1[2] ^ (~n2[2] & n3[2]);
                state[1][3] = n1[3] ^ (~n2[3] & n3[3]);
                state[1][4] = n1[4] ^ (~n2[4] & n3[4]);

                state[2][0] = n2[0] ^ (~n3[0] & n4[0]);
                state[2][1] = n2[1] ^ (~n3[1] & n4[1]);
                state[2][2] = n2[2] ^ (~n3[2] & n4[2]);
                state[2][3] = n2[3] ^ (~n3[3] & n4[3]);
                state[2][4] = n2[4] ^ (~n3[4] & n4[4]);

                state[3][0] = n3[0] ^ (~n4[0] & n0[0]);
                state[3][1] = n3[1] ^ (~n4[1] & n0[1]);
                state[3][2] = n3[2] ^ (~n4[2] & n0[2]);
                state[3][3] = n3[3] ^ (~n4[3] & n0[3]);
                state[3][4] = n3[4] ^ (~n4[4] & n0[4]);

                state[4][0] = n4[0] ^ (~n0[0] & n1[0]);
                state[4][1] = n4[1] ^ (~n0[1] & n1[1]);
                state[4][2] = n4[2] ^ (~n0[2] & n1[2]);
                state[4][3] = n4[3] ^ (~n0[3] & n1[3]);
                state[4][4] = n4[4] ^ (~n0[4] & n1[4]);
            }
        }
        
        private static long RotL(long v, int n)
        {
            unchecked
            {
                var x = (ulong)v;
                return (long)((x << n) | (x >> (64 - n)));
            }
        }
        
        private static void DirectLongToBytes(long value, SplitByteArray destination, int offset)
        {
            if (offset + 7 >= destination.Size)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            
            destination[offset] = (byte)(value & 0xFF);
            destination[offset + 1] = (byte)((value >> 8) & 0xFF);
            destination[offset + 2] = (byte)((value >> 16) & 0xFF);
            destination[offset + 3] = (byte)((value >> 24) & 0xFF);
            destination[offset + 4] = (byte)((value >> 32) & 0xFF);
            destination[offset + 5] = (byte)((value >> 40) & 0xFF);
            destination[offset + 6] = (byte)((value >> 48) & 0xFF);
            destination[offset + 7] = (byte)((ulong)value >> 56);
        }
    }
}