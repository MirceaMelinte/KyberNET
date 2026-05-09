namespace KyberNET.Exceptions;

/// <summary>
/// Thrown when the byte length of a key or ciphertext does not match any known ML-KEM parameter set
/// </summary>
public sealed class UnsupportedKyberVariantException(string message)
    : Exception($"This ML-KEM variant is not yet supported. Reason: {message}");