namespace KyberNET.Infrastructure;

using Constants;

internal static class Encoding
{
    public static void Decompress(int[] coefficients, int bitSize)
    {
        for (var i = 0; i < coefficients.Length; i++)
        {
            coefficients[i] = ((KyberConstants.Q * coefficients[i]) + (1 << (bitSize - 1))) >> bitSize;
        }
    }

    public static int[] FastByteDecode(byte[] bytes, int bitSize, int offset = 0, int? length = null)
    {
        var len = length ?? bytes.Length - offset;
        var result = new int[len * 8 / bitSize];
        var lastIndex = offset + len - 1;
        var byteIndex = offset;
        var usableBits = 8;
        var currentByte = bytes[byteIndex] & 0xFF;

        for (var i = 0; i < result.Length; i++)
        {
            var accumulator = 0;
            var ingestedBits = 0;

            while (ingestedBits < bitSize)
            {
                var canIngest = Math.Min(usableBits, bitSize - ingestedBits);
                var mask = 0xFF >> (8 - canIngest);

                accumulator |= (currentByte & mask) << ingestedBits;
                currentByte >>= canIngest;
                usableBits -= canIngest;
                ingestedBits += canIngest;

                if (usableBits == 0 && byteIndex < lastIndex)
                {
                    byteIndex++;
                    currentByte = bytes[byteIndex] & 0xFF;
                    usableBits = 8;
                }
            }

            result[i] = accumulator;
        }

        return result;
    }

    public static void ByteEncodeInto(byte[] output, int destIndex, int[] vector, int bitSize)
    {
        var outputIndex = 0;
        var bitIndex = 0;
        var temp = 0;

        for (var i = 0; i < vector.Length; i++)
        {
            var value = ModMath.BarrettReduce(ModMath.MontgomeryReduce(vector[i]));

            for (var j = 0; j < bitSize; j++)
            {
                temp |= ((value >> j) & 1) << bitIndex++;

                if (bitIndex == 8)
                {
                    output[destIndex + outputIndex++] = (byte)temp;
                    bitIndex = 0;
                    temp = 0;
                }
            }
        }
    }

    public static void CompressAndEncodeInto(byte[] output, int destIndex, int[] vector, int bitSize)
    {
        var mask = 1 << bitSize;
        var outputIndex = 0;
        var bitIndex = 0;
        var temp = 0;

        for (var i = 0; i < vector.Length; i++)
        {
            var value = ((mask * ModMath.MontgomeryReduce(vector[i])) + KyberConstants.Q_HALF) / KyberConstants.Q;

            for (var j = 0; j < bitSize; j++)
            {
                temp |= ((value >> j) & 1) << bitIndex++;

                if (bitIndex == 8)
                {
                    output[destIndex + outputIndex++] = (byte)temp;
                    bitIndex = 0;
                    temp = 0;
                }
            }
        }
    }

    public static int[] ExpandMuse(byte[] bytes)
    {
        var shorts = new int[bytes.Length * 8];
        var decompressConstant = ModMath.ToMontgomeryForm(KyberConstants.Q_HALF + 1);

        for (var i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i];

            for (var j = 0; j < 8; j++)
            {
                shorts[(i * 8) + j] = ((b >> j) & 1) * decompressConstant;
            }
        }

        return shorts;
    }

    public static void VectorToMontVector(int[] vector)
    {
        for (var i = 0; i < vector.Length; i++)
        {
            vector[i] = ModMath.BarrettReduce(ModMath.ToMontgomeryForm(vector[i]));
        }
    }
}