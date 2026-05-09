namespace KyberNET.Hashing;

internal static class KeccakHash
{
    /// <summary>
    /// Absorb pre-chunked input (SplitByteArray view per chunk) + padding into state
    /// </summary>
    public static void GenerateDirect(
        KeccakParameter parameter,
        (byte[][] chunks, int lastChunkUsed) input,
        FlexiByte suffix,
        SplitByteArray stateBuffer,
        long[][] state)
    {
        var addAnother = input.lastChunkUsed == parameter.BYTERATE;
        var total = input.chunks.Length + (addAnother ? 1 : 0);
        var validated = new byte[total][];

        for (var i = 0; i < total; i++)
        {
            validated[i] = i == input.chunks.Length
                ? new byte[parameter.BYTERATE]
                : input.chunks[i];
        }

        // pad last chunk at position (addAnother ? 0 : lastChunkUsed)
        KeccakMath.Pad10n1Direct(validated[^1], addAnother ? 0 : input.lastChunkUsed, suffix);

        // absorb each block
        foreach (var block in validated)
        {
            stateBuffer.A = block;

            for (var x = 0; x < 5; x++)
            {
                for (var y = 0; y < 5; y++)
                {
                    state[x][y] ^= KeccakMath.GetLongAt(stateBuffer, x, y, parameter.BYTERATE);
                }
            }

            KeccakMath.DirectPermute(state);
        }
    }

    /// <summary>
    /// Squeezes output bytes after GenerateDirect
    /// </summary>
    public static byte[] GenerateDirectOutput(
        KeccakParameter parameter,
        int length,
        (byte[][] chunks, int lastChunkUsed) input,
        FlexiByte suffix)
    {
        var stateBuffer = new SplitByteArray(new byte[parameter.BYTERATE], new byte[200 - parameter.BYTERATE]);
        var state = NewState();

        GenerateDirect(parameter, input, suffix, stateBuffer, state);

        stateBuffer.A = new byte[parameter.BYTERATE];

        var output = new byte[length];
        var totalOut = 0;

        while (totalOut < length)
        {
            KeccakMath.DirectMatrixToBytes(state, stateBuffer);

            var toCopy = Math.Min(length - totalOut, parameter.BYTERATE);
            Buffer.BlockCopy(stateBuffer.A, 0, output, totalOut, toCopy);

            totalOut += toCopy;

            if (totalOut < length)
            {
                KeccakMath.DirectPermute(state);
            }
        }

        return output;
    }

    public static long[][] NewState()
    {
        var state = new long[5][];

        for (var i = 0; i < 5; i++)
        {
            state[i] = new long[5];
        }

        return state;
    }
}