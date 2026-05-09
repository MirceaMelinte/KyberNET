namespace KyberNET.Hashing;

internal abstract class AbstractKeccakFunction(int initialCapacity)
    : IKeccakInstance
{
    private readonly UniversalDigestor digestor = new(initialCapacity);

    public abstract KeccakParameter Parameter { get; }

    public void Update(byte @byte) => digestor.DigestSingle(@byte);

    public void Update(byte[] bytes) => digestor.Digest(bytes);

    public void Update(byte[] bytes, int offset, int length) => digestor.Digest(bytes, offset, length);

    public byte[] Digest()
    {
        digestor.Digest(AddLast());
        return ComputeDigest(digestor.ExtractChunksAndReset());
    }

    public byte[] Digest(byte @byte)
    {
        digestor.DigestSingle(@byte);
        digestor.Digest(AddLast());
        return ComputeDigest(digestor.ExtractChunksAndReset());
    }

    public byte[] Digest(byte[] bytes)
    {
        digestor.Digest(bytes);
        digestor.Digest(AddLast());
        return ComputeDigest(digestor.ExtractChunksAndReset());
    }

    public byte[] Digest(byte[] bytes, int offset, int length)
    {
        digestor.Digest(bytes, offset, length);
        digestor.Digest(AddLast());
        return ComputeDigest(digestor.ExtractChunksAndReset());
    }

    public HashOutputStream Stream()
    {
        digestor.Digest(AddLast());
        return ComputeAsHashStream(digestor.ExtractChunksAndReset());
    }

    public HashOutputStream Stream(byte[] bytes)
    {
        digestor.Digest(bytes);
        digestor.Digest(AddLast());
        return ComputeAsHashStream(digestor.ExtractChunksAndReset());
    }

    protected virtual byte[] AddLast() => [];

    protected abstract byte[] ComputeDigest((byte[][] chunks, int lastChunkUsed) chunks);

    protected abstract HashOutputStream ComputeAsHashStream((byte[][] chunks, int lastChunkUsed) chunks);
}