namespace KyberNET.Exceptions;

/// <summary>
/// Thrown when a requested digest size exceeds the maximum supported length
/// </summary>
public sealed class DigestTooLargeException(long size)
    : Exception($"This digest of size {size} is too large. It must be less than or equal to {int.MaxValue}");