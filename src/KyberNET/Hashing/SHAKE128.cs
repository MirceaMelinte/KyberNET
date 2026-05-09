namespace KyberNET.Hashing;

internal sealed class SHAKE128(int? outputLength = null)
    : AbstractKeccakFunction(KeccakParameter.SHAKE_128.BYTERATE)
{
    public int OutputLength { get; } = outputLength ?? (KeccakParameter.SHAKE_128.MIN_LENGTH / 8);

    public override KeccakParameter Parameter => KeccakParameter.SHAKE_128;

    public static HashInputStream NewInputStream() =>
        new(KeccakParameter.SHAKE_128, KeccakParameter.SHAKE_128.MAX_LENGTH / 8);

    protected override byte[] ComputeDigest((byte[][] chunks, int lastChunkUsed) chunks) =>
        KeccakHash.GenerateDirectOutput(KeccakParameter.SHAKE_128, OutputLength, chunks, KeccakParameter.SHAKE_128.SUFFIX);

    protected override HashOutputStream ComputeAsHashStream((byte[][] chunks, int lastChunkUsed) chunks) =>
        new(KeccakParameter.SHAKE_128, KeccakParameter.SHAKE_128.SUFFIX, chunks, KeccakParameter.SHAKE_128.MAX_LENGTH / 8);
}