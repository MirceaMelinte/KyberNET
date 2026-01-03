namespace KyberNET.Exceptions
{
    using System;

    internal sealed class DigestTooLargeException(long size)
        : Exception($"This digest of size {size} is too large. It must be less than or equal to {int.MaxValue}");
}