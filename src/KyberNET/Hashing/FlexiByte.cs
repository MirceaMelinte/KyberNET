namespace KyberNET.Hashing
{
    using System;

    internal readonly struct FlexiByte(byte value, int bitIndex)
        : IComparable<byte>
    {
        private byte Byte { get; } = value;

        public int BitIndex { get; } = Math.Clamp(bitIndex, 0, 7);

        public byte ToByte() => Byte;

        public int CompareTo(byte other) => Byte.CompareTo(other);

        public static FlexiByte FromString(string bits)
        {
            var input = bits?.Trim() ?? string.Empty;

            if (input.Length > 8)
            {
                throw new ArgumentException("Cannot convert from a byte consisting of more than 8 binary values");
            }

            byte v = 0;

            var bitIdx = Math.Min(input.Length, 8) - 1;

            for (var i = 0; i <= bitIdx; i++)
            {
                if (input[bitIdx - i] == '1')
                {
                    v = (byte)(v | (1 << i));
                }
            }

            return new FlexiByte(v, bitIdx);
        }
    }
}