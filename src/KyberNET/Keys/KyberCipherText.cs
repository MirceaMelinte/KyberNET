namespace KyberNET.Keys;

using Constants;
using Internal;

/// <summary>
/// An ML-KEM ciphertext produced by encapsulation
/// </summary>
public sealed class KyberCipherText : IEquatable<KyberCipherText>
{
    /// <summary>
    /// The ML-KEM parameter set this ciphertext belongs to
    /// </summary>
    public KyberParameter Parameter { get; }

    internal byte[] EncodedCoefficients { get; }
    internal byte[] EncodedTerms { get; }

    internal KyberCipherText(KyberParameter parameter, byte[] encodedCoefficients, byte[] encodedTerms)
    {
        Parameter = parameter;
        EncodedCoefficients = (byte[])encodedCoefficients.Clone();
        EncodedTerms = (byte[])encodedTerms.Clone();
    }

    /// <summary>
    /// Returns a copy of the serialized ciphertext bytes.
    /// Each access allocates a new array.
    /// Capture in a local variable declaration to avoid repeated allocations.
    /// </summary>
    /// <example>
    /// <code>
    /// // Bad: allocates twice
    /// hash.Update(cipherText.FullBytes);
    /// store.Save(cipherText.FullBytes);
    ///
    /// // Good: allocates once
    /// var ctBytes = cipherText.FullBytes;
    /// hash.Update(ctBytes);
    /// store.Save(ctBytes);
    /// </code>
    /// </example>
    public byte[] FullBytes
    {
        get
        {
            var output = new byte[Parameter.CiphertextLength];
            WriteTo(output);
            return output;
        }
    }

    /// <summary>
    /// Writes the serialized ciphertext bytes into the destination span.
    /// The span must be at least <see cref="KyberParameter.CiphertextLength"/> bytes long.
    /// </summary>
    public void WriteTo(Span<byte> destination)
    {
        EncodedCoefficients.AsSpan().CopyTo(destination);
        EncodedTerms.AsSpan().CopyTo(destination[EncodedCoefficients.Length..]);
    }

    /// <summary>
    /// Decapsulates this ciphertext and recovers the shared secret key.
    /// Equivalent to <see cref="KyberDecapsulationKey.Decapsulate"/>.
    /// </summary>
    public byte[] Decapsulate(KyberDecapsulationKey decapsulationKey)
        => KyberAgreement.Decapsulate(decapsulationKey, this);

    /// <summary>
    /// Creates a deep copy of this ciphertext
    /// </summary>
    public KyberCipherText Copy()
        => new(Parameter, EncodedCoefficients, EncodedTerms);

    /// <inheritdoc />
    public bool Equals(KyberCipherText? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return Parameter == other.Parameter
            && EncodedCoefficients.AsSpan().SequenceEqual(other.EncodedCoefficients)
            && EncodedTerms.AsSpan().SequenceEqual(other.EncodedTerms);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
        => obj is KyberCipherText other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Parameter);
        foreach (var b in EncodedCoefficients)
        {
            hash.Add(b);
        }
        foreach (var b in EncodedTerms)
        {
            hash.Add(b);
        }
        return hash.ToHashCode();
    }

    /// <summary>
    /// Equality operator
    /// </summary>
    public static bool operator ==(KyberCipherText? left, KyberCipherText? right)
        => Equals(left, right);

    /// <summary>
    /// Inequality operator
    /// </summary>
    public static bool operator !=(KyberCipherText? left, KyberCipherText? right)
        => !Equals(left, right);

    /// <summary>
    /// Deserializes a ciphertext from byte representation
    /// </summary>
    public static KyberCipherText FromBytes(byte[] bytes)
        => FromBytes(bytes.AsSpan());

    /// <summary>
    /// Deserializes a ciphertext from byte representation
    /// </summary>
    public static KyberCipherText FromBytes(ReadOnlySpan<byte> bytes)
    {
        var parameter = KyberParameter.FindByCipherTextSize(bytes.Length);
        var encodedCoefficientsSize = KyberConstants.N_BYTES * (parameter.Du * parameter.K);

        return new KyberCipherText(
            parameter,
            bytes[..encodedCoefficientsSize].ToArray(),
            bytes[encodedCoefficientsSize..].ToArray());
    }
}