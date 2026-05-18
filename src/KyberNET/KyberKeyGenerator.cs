namespace KyberNET;

using Constants;
using Exceptions;
using Hashing;
using Keys;

/// <summary>
/// Generates ML-KEM key pairs for a given parameter set
/// </summary>
public static class KyberKeyGenerator
{
    /// <summary>
    /// Generates a new ML-KEM key pair for the specified parameter set
    /// </summary>
    public static KyberKEMKeyPair Generate(KyberParameter parameter, IRandomProvider? randomProvider = null)
    {
        var randomSeed = new byte[KyberConstants.N_BYTES];
        var pkeSeed = new byte[KyberConstants.N_BYTES];

        var rng = randomProvider ?? DefaultRandomProvider.Instance;
        rng.FillWithRandom(randomSeed);
        rng.FillWithRandom(pkeSeed);

        return Generate(parameter, randomSeed, pkeSeed);
    }

    internal static KyberKEMKeyPair Generate(KyberParameter parameter, byte[] randomSeed, byte[] pkeSeed)
    {
        if (randomSeed.All(b => b == 0) || pkeSeed.All(b => b == 0))
        {
            throw new RandomBitGenerationException();
        }

        var pkeKeyPair = PkeKeyGenerator.Generate(parameter, pkeSeed);

        Array.Clear(pkeSeed, 0, pkeSeed.Length);

        var hash = new SHA3_256().Digest(pkeKeyPair.EncryptionKey.FullBytes);

        return new KyberKEMKeyPair(
            new KyberEncapsulationKey(pkeKeyPair.EncryptionKey),
            new KyberDecapsulationKey(pkeKeyPair.DecryptionKey, pkeKeyPair.EncryptionKey, hash, randomSeed));
    }
}