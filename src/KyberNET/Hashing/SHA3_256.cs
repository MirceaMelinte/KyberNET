namespace KyberNET.Hashing
{
    internal sealed class SHA3_256(int? outputLength = null)
        : AbstractKeccakFunction(KeccakParameter.SHA3_256.BYTERATE)
    {
        public int OutputLength { get; } = outputLength ?? (KeccakParameter.SHA3_256.MIN_LENGTH / 8); // 32

        public override KeccakParameter Parameter => KeccakParameter.SHA3_256;
        
        public static HashInputStream NewInputStream() =>
            new(KeccakParameter.SHA3_256, KeccakParameter.SHA3_256.MAX_LENGTH / 8); // 32

        protected override byte[] ComputeDigest((byte[][] chunks, int lastChunkUsed) chunks) =>
            KeccakHash.GenerateDirectOutput(KeccakParameter.SHA3_256, OutputLength, chunks, KeccakParameter.SHA3_256.SUFFIX);

        // non-extendable; maxOutputLength is fixed to OutputLength
        protected override HashOutputStream ComputeAsHashStream((byte[][] chunks, int lastChunkUsed) chunks) =>
            new(KeccakParameter.SHA3_256, KeccakParameter.SHA3_256.SUFFIX, chunks, OutputLength);
    }
}