namespace KyberNET.Hashing;

internal sealed class SHA3_512(int? outputLength = null)
    : AbstractKeccakFunction(KeccakParameter.SHA3_512.BYTERATE)
{
    public int OutputLength { get; } = outputLength ?? (KeccakParameter.SHA3_512.MIN_LENGTH / 8); // 64

    public override KeccakParameter Parameter => KeccakParameter.SHA3_512;

    public static HashInputStream NewInputStream() =>
        new(KeccakParameter.SHA3_512, KeccakParameter.SHA3_512.MAX_LENGTH / 8); // 64

    protected override byte[] ComputeDigest((byte[][] chunks, int lastChunkUsed) chunks) =>
        KeccakHash.GenerateDirectOutput(KeccakParameter.SHA3_512, OutputLength, chunks, KeccakParameter.SHA3_512.SUFFIX);

    // non-extendable; maxOutputLength is fixed to OutputLength
    protected override HashOutputStream ComputeAsHashStream((byte[][] chunks, int lastChunkUsed) chunks) =>
        new(KeccakParameter.SHA3_512, KeccakParameter.SHA3_512.SUFFIX, chunks, OutputLength);
}