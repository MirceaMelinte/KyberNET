namespace KyberNET.Hashing;

internal sealed class SHAKE256(int? outputLength = null)
    : AbstractKeccakFunction(KeccakParameter.SHAKE_256.BYTERATE)
{
    public int OutputLength { get; } = outputLength ?? (KeccakParameter.SHAKE_256.MIN_LENGTH / 8);

    public override KeccakParameter Parameter => KeccakParameter.SHAKE_256;

    public static HashInputStream NewInputStream() =>
        new(KeccakParameter.SHAKE_256, KeccakParameter.SHAKE_256.MAX_LENGTH / 8);

    protected override byte[] ComputeDigest((byte[][] chunks, int lastChunkUsed) chunks) =>
        KeccakHash.GenerateDirectOutput(KeccakParameter.SHAKE_256, OutputLength, chunks, KeccakParameter.SHAKE_256.SUFFIX);

    protected override HashOutputStream ComputeAsHashStream((byte[][] chunks, int lastChunkUsed) chunks) =>
        new(KeccakParameter.SHAKE_256, KeccakParameter.SHAKE_256.SUFFIX, chunks, KeccakParameter.SHAKE_256.MAX_LENGTH / 8);
}