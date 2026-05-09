namespace KyberNET.Exceptions;

/// <summary>
/// Thrown when key material fails validation (for example coefficients out of range or hash mismatch)
/// </summary>
public sealed class InvalidKyberKeyException(string message)
    : Exception($"Provided key may not be an ML-KEM key. Reason: {message}");