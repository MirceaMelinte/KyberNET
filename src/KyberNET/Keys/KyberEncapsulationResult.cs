namespace KyberNET.Keys;

/// <summary>
/// The result of an ML-KEM encapsulation: a shared secret and corresponding ciphertext
/// </summary>
public sealed class KyberEncapsulationResult
{
    private readonly byte[] sharedSecretKey;

    /// <summary>
    /// Returns a copy of the shared secret key.
    /// Each access allocates a new array.
    /// Capture in a local variable declaration to avoid repeated allocations.
    /// </summary>
    /// <example>
    /// <code>
    /// // Bad: allocates twice
    /// hash.Update(result.SharedSecretKey);
    /// store.Save(result.SharedSecretKey);
    ///
    /// // Good: allocates once
    /// var secret = result.SharedSecretKey;
    /// hash.Update(secret);
    /// store.Save(secret);
    /// </code>
    /// </example>
    public byte[] SharedSecretKey => (byte[])sharedSecretKey.Clone();

    /// <summary>
    /// The ciphertext to send for decapsulating.
    /// Safe to send over an insecure channel of communication.
    /// </summary>
    public KyberCipherText CipherText { get; }

    internal KyberEncapsulationResult(byte[] sharedSecretKey, KyberCipherText cipherText)
    {
        this.sharedSecretKey = (byte[])sharedSecretKey.Clone();
        CipherText = cipherText;
    }
}