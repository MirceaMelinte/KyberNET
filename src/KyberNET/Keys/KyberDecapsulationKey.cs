namespace KyberNET.Keys;

using Constants;
using Exceptions;
using Hashing;
using Infrastructure;
using Internal;

/// <summary>
/// An ML-KEM decapsulation (private) key used to recover shared secrets from ciphertexts
/// </summary>
public sealed class KyberDecapsulationKey
    : IKyberKEMKey, IDisposable
{
    private bool disposed;

    internal KyberDecryptionKey Key { get; }
    internal KyberEncryptionKey EncryptionKey { get; }
    internal byte[] Hash { get; }
    internal byte[] RandomSeed { get; }

    /// <summary>
    /// The ML-KEM parameter set this key belongs to
    /// </summary>
    public KyberParameter Parameter { get; }

    IKyberPKEKey IKyberKEMKey.Key => Key;

    internal KyberDecapsulationKey(KyberDecryptionKey key, KyberEncryptionKey encryptionKey, byte[] hash, byte[] randomSeed)
    {
        Key = key;
        EncryptionKey = encryptionKey;
        Hash = (byte[])hash.Clone();
        RandomSeed = (byte[])randomSeed.Clone();
        Parameter = key.Parameter;

        var encryptionKeyHash = new SHA3_256().Digest(encryptionKey.FullBytes);

        if (Subtle.Compare(encryptionKeyHash, hash) != 0)
        {
            throw new InvalidKyberKeyException("Hash check failed! Invalid descapsulation key");
        }
    }

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
    public byte[] FullBytes
    {
        get
        {
            var output = new byte[Parameter.DecapsulationKeyLength];
            WriteTo(output);
            return output;
        }
    }

    /// <summary>
    /// Writes the serialized key bytes into the destination span.
    /// The span must be at least <see cref="KyberParameter.DecapsulationKeyLength"/> bytes long.
    /// </summary>
    public void WriteTo(Span<byte> destination)
    {
        var offset = 0;

        Key.KeyBytes.AsSpan().CopyTo(destination);
        offset += Key.KeyBytes.Length;

        EncryptionKey.WriteTo(destination[offset..]);
        offset += Parameter.EncapsulationKeyLength;

        Hash.AsSpan().CopyTo(destination[offset..]);
        offset += Hash.Length;

        RandomSeed.AsSpan().CopyTo(destination[offset..]);
    }

    /// <summary>
    /// Performs ML-KEM decapsulation, recovering the shared secret from a ciphertext
    /// </summary>
    public byte[] Decapsulate(KyberCipherText cipherText) => KyberAgreement.Decapsulate(this, cipherText);

    /// <summary>
    /// Deserializes a decapsulation key from its byte representation.
    /// </summary>
    public static KyberDecapsulationKey FromBytes(byte[] bytes)
        => FromBytes(bytes.AsSpan());

    /// <summary>
    /// Deserializes a decapsulation key from its byte representation.
    /// </summary>
    public static KyberDecapsulationKey FromBytes(ReadOnlySpan<byte> bytes)
    {
        var parameter = KyberParameter.FindByDecapsulationKeySize(bytes.Length);

        var offset = 0;

        var decryptionKey = KyberDecryptionKey.FromBytes(bytes[..parameter.DecryptionKeyLength]);
        offset += parameter.DecryptionKeyLength;

        var encryptionKey = KyberEncryptionKey.FromBytes(bytes.Slice(offset, parameter.EncryptionKeyLength));
        offset += parameter.EncryptionKeyLength;

        var hash = bytes.Slice(offset, KyberConstants.N_BYTES).ToArray();
        offset += KyberConstants.N_BYTES;

        var randomSeed = bytes.Slice(offset, KyberConstants.N_BYTES).ToArray();

        return new KyberDecapsulationKey(decryptionKey, encryptionKey, hash, randomSeed);
    }

    public void Dispose()
    {
        if (!disposed)
        {
            Array.Clear(Hash, 0, Hash.Length);
            Array.Clear(RandomSeed, 0, RandomSeed.Length);
            
            Key.Dispose();
            
            disposed = true;
        }
    }
}