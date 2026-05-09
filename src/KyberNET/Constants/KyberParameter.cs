namespace KyberNET.Constants;

using Exceptions;

/// <summary>
/// Identifies an ML-KEM parameter set (ML-KEM-512, ML-KEM-768, or ML-KEM-1024)
/// </summary>
public sealed class KyberParameter
{
    /// <summary>ML-KEM-512 parameter set (NIST security level 1)</summary>
    public static readonly KyberParameter MlKem512 = new(2, 3, 2, 10, 4, "ML-KEM-512");

    /// <summary>ML-KEM-768 parameter set (NIST security level 3)</summary>
    public static readonly KyberParameter MlKem768 = new(3, 2, 2, 10, 4, "ML-KEM-768");

    /// <summary>ML-KEM-1024 parameter set (NIST security level 5)</summary>
    public static readonly KyberParameter MlKem1024 = new(4, 2, 2, 11, 5, "ML-KEM-1024");

    private static readonly KyberParameter[] All = [MlKem512, MlKem768, MlKem1024];

    /// <summary>The name of this parameter set (for example, "ML-KEM-768")</summary>
    public string Name { get; }

    internal int K { get; }

    internal int Eta1 { get; }
    internal int Eta2 { get; }

    internal int Du { get; }
    internal int Dv { get; }

    internal int CiphertextLength { get; }

    internal int DecryptionKeyLength { get; }
    internal int EncryptionKeyLength { get; }

    internal int EncapsulationKeyLength { get; }
    internal int DecapsulationKeyLength { get; }

    private KyberParameter(int k, int eta1, int eta2, int du, int dv, string name)
    {
        K = k;

        Eta1 = eta1;
        Eta2 = eta2;

        Du = du;
        Dv = dv;
        Name = name;

        CiphertextLength = KyberConstants.N_BYTES * ((Du * K) + Dv);

        DecryptionKeyLength = KyberConstants.ENCODE_SIZE * K;
        EncryptionKeyLength = DecryptionKeyLength + KyberConstants.N_BYTES;

        EncapsulationKeyLength = EncryptionKeyLength;
        DecapsulationKeyLength = EncapsulationKeyLength + DecryptionKeyLength + (2 * KyberConstants.N_BYTES);
    }

    /// <inheritdoc />
    public override string ToString() => Name;

    internal static KyberParameter FindByCipherTextSize(int length)
    {
        foreach (var param in All)
        {
            if (param.CiphertextLength == length)
            {
                return param;
            }
        }

        throw new UnsupportedKyberVariantException("Cipher Text byte length is either bigger or smaller than expected");
    }

    internal static KyberParameter FindByEncryptionKeySize(int length)
    {
        foreach (var param in All)
        {
            if (param.EncapsulationKeyLength == length)
            {
                return param;
            }
        }

        throw new UnsupportedKyberVariantException("Encryption Key byte length is either bigger or smaller than expected");
    }

    internal static KyberParameter FindByEncapsulationKeySize(int length)
    {
        try
        {
            return FindByEncryptionKeySize(length);
        }
        catch (UnsupportedKyberVariantException)
        {
            throw new UnsupportedKyberVariantException("Encapsulation Key byte length is either bigger or smaller than expected");
        }
    }

    internal static KyberParameter FindByDecryptionKeySize(int length)
    {
        foreach (var @param in All)
        {
            if (@param.DecryptionKeyLength == length)
            {
                return @param;
            }
        }

        throw new UnsupportedKyberVariantException("Decryption Key byte length is either bigger or smaller than expected");
    }

    internal static KyberParameter FindByDecapsulationKeySize(int length)
    {
        foreach (var @param in All)
        {
            if (@param.DecapsulationKeyLength == length)
            {
                return @param;
            }
        }

        throw new UnsupportedKyberVariantException("Decapsulation Key byte length is either bigger or smaller than expected");
    }
}