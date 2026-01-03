namespace KyberNET.Exceptions
{
    using System;

    public sealed class UnsupportedKyberVariantException(string message)
        : Exception($"This ML-KEM variant is not yet supported. Reason: {message}");
}