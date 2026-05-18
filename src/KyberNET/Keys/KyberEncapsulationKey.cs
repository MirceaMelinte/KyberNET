namespace KyberNET.Keys;

using Constants;
using Internal;

/// <summary>
/// An ML-KEM encapsulation (public) key used to create shared secrets
/// </summary>
public sealed class KyberEncapsulationKey
    : IKyberKEMKey
{
    internal KyberEncryptionKey Key { get; }

    IKyberPKEKey IKyberKEMKey.Key => Key;

    internal KyberEncapsulationKey(KyberEncryptionKey key)
    {
        Key = key;
    }

    /// <summary>
    /// The ML-KEM parameter set this key belongs to
    /// </summary>
    public KyberParameter Parameter => Key.Parameter;

    /// <summary>
    /// Returns a copy of the serialized key bytes.
    /// Each access allocates a new array.
    /// Capture in a local variable declaration to avoid repeated allocations.
    /// </summary>
    /// <example>
    /// <code>
    /// // Bad: allocates twice
    /// hash.Update(key.FullBytes);
    /// store.Save(key.FullBytes);
    ///
    /// // Good: allocates once
    /// var keyBytes = key.FullBytes;
    /// hash.Update(keyBytes);
    /// store.Save(keyBytes);
    /// </code>
    /// </example>
    public byte[] FullBytes => Key.FullBytes;

    /// <summary>
    /// Writes the serialized key bytes into the destination span.
    /// The span must be at least <see cref="KyberParameter.EncapsulationKeyLength"/> bytes long.
    /// </summary>
    public void WriteTo(Span<byte> destination) => Key.WriteTo(destination);

    /// <summary>
    /// Performs ML-KEM encapsulation, producing a shared secret and ciphertext
    /// </summary>
    public KyberEncapsulationResult Encapsulate(IRandomProvider? randomProvider = null)
    {
        var plainText = new byte[KyberConstants.N_BYTES];

        var rng = randomProvider ?? DefaultRandomProvider.Instance;
        rng.FillWithRandom(plainText);

        return KyberAgreement.Encapsulate(this, plainText);
    }

    /// <summary>
    /// Deserializes an encapsulation key from its byte representation
    /// </summary>
    public static KyberEncapsulationKey FromBytes(byte[] bytes) => new(KyberEncryptionKey.FromBytes(bytes));

    /// <summary>
    /// Deserializes an encapsulation key from its byte representation
    /// </summary>
    public static KyberEncapsulationKey FromBytes(ReadOnlySpan<byte> bytes) => new(KyberEncryptionKey.FromBytes(bytes));
}
