namespace KyberNET.Infrastructure
{
    using System;

    /// <summary>
    /// Bit <-> byte marshalling to be used by the Kyber encoder/decoder
    /// </summary>
    public static class BitOps
    {
        public static int ToInt(this bool b) => b ? 1 : 0;

        /// <summary>
        /// Packs a bool array (least significant bit first) into a byte array
        /// </summary>
        public static byte[] BitsToBytes(bool[] bits)
        {
            var bytes = new byte[bits.Length >> 3];

            for (var i = 0; i < bytes.Length; i++)
            {
                var off = i << 3;
                bytes[i] = (byte)(
                    bits[off + 0].ToInt() |
                    bits[off + 1].ToInt() << 1 |
                    bits[off + 2].ToInt() << 2 |
                    bits[off + 3].ToInt() << 3 |
                    bits[off + 4].ToInt() << 4 |
                    bits[off + 5].ToInt() << 5 |
                    bits[off + 6].ToInt() << 6 |
                    bits[off + 7].ToInt() << 7);
            }

            return bytes;
        }

        /// <summary>
        /// Unpacks a byte array into a bool array (least significant bit first)
        /// </summary>
        public static bool[] BytesToBits(ReadOnlySpan<byte> bytes)
        {
            var bits = new bool[bytes.Length << 3];

            for (var i = 0; i < bytes.Length; i++)
            {
                var b = bytes[i];
                var off = i << 3;
                
                bits[off + 0] = (b & 0b0000_0001) != 0;
                bits[off + 1] = (b & 0b0000_0010) != 0;
                bits[off + 2] = (b & 0b0000_0100) != 0;
                bits[off + 3] = (b & 0b0000_1000) != 0;
                bits[off + 4] = (b & 0b0001_0000) != 0;
                bits[off + 5] = (b & 0b0010_0000) != 0;
                bits[off + 6] = (b & 0b0100_0000) != 0;
                bits[off + 7] = (b & 0b1000_0000) != 0;
            }

            return bits;
        }
    }
}