namespace KyberNET.Exceptions
{
    using System;

    public sealed class InvalidKyberKeyException(string message)
        : Exception($"Provided key may not be an ML-KEM key. Reason: {message}");
}