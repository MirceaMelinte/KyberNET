namespace KyberNET.Exceptions
{
    using System;

    /// <summary>
    /// Thrown when the random source produces an all-zero seed, indicating a potentially faulty entropy source
    /// </summary>
    public sealed class RandomBitGenerationException()
        : Exception("Random bit generation produced an all-zero seed. The random source may be faulty");
}