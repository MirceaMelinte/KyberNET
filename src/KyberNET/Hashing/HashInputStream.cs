namespace KyberNET.Hashing;

internal sealed class HashInputStream
{
    private KeccakParameter PARAMETER { get; }

    private FlexiByte SUFFIX => PARAMETER.SUFFIX;

    private readonly long[][] state = KeccakHash.NewState();
    private readonly SplitByteArray buffer;

    private readonly int maxOutputLength;

    private int inputPosition;
    private bool closed;

    internal HashInputStream(KeccakParameter parameter, int maxOutputLength)
    {
        PARAMETER = parameter;
        buffer = new SplitByteArray(new byte[PARAMETER.BYTERATE], new byte[200 - PARAMETER.BYTERATE]);
        this.maxOutputLength = maxOutputLength;
    }

    private void TryPermuteIfFull()
    {
        if (inputPosition < buffer.A.Length)
        {
            return;
        }

        for (var x = 0; x < 5; x++)
        {
            for (var y = 0; y < 5; y++)
            {
                state[x][y] ^= KeccakMath.GetLongAt(buffer, x, y, PARAMETER.BYTERATE);
            }
        }

        KeccakMath.DirectPermute(state);

        Array.Fill(buffer.A, (byte)0);
        inputPosition = 0;
    }

    private void OnAbsorb(byte[] bytes, int offset, int length)
    {
        if (closed)
        {
            throw new InvalidOperationException("Hash output stream already closed");
        }

        var index = offset;
        var end = offset + length;

        while (index < end)
        {
            var toCopy = Math.Min(end - index, buffer.A.Length - inputPosition);
            Buffer.BlockCopy(bytes, index, buffer.A, inputPosition, toCopy);

            inputPosition += toCopy;
            index += toCopy;

            TryPermuteIfFull();
        }
    }

    private void OnAbsorbOne(byte b)
    {
        if (closed)
        {
            throw new InvalidOperationException("Hash output stream already closed");
        }

        buffer[inputPosition++] = b;
        TryPermuteIfFull();
    }

    private void BeforeClose() { }

    public void Write(byte @byte) => OnAbsorbOne(@byte);

    public void Write(byte[] bytes) => OnAbsorb(bytes, 0, bytes.Length);

    public void Write(byte[] bytes, int offset, int length) => OnAbsorb(bytes, offset, length);

    public HashOutputStream Close()
    {
        if (closed)
        {
            throw new InvalidOperationException("Hash output stream already closed");
        }

        BeforeClose();

        KeccakMath.Pad10n1Direct(buffer.A, inputPosition, SUFFIX);
        inputPosition = buffer.A.Length;
        TryPermuteIfFull();

        closed = true;
        return new HashOutputStream(PARAMETER, state, maxOutputLength);
    }
}