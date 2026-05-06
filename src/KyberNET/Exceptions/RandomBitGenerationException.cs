namespace KyberNET.Exceptions
{
    using System;

    public sealed class RandomBitGenerationException()
        : Exception("Random bit generation produced an all-zero seed. The random source may be faulty");
}