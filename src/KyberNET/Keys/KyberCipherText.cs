namespace KyberNET.Keys;

using Constants;

/// <summary>
/// An ML-KEM ciphertext produced by encapsulation
/// </summary>
public sealed class KyberCipherText
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