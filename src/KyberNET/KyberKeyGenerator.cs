namespace KyberNET;

using Constants;
using Exceptions;
using Hashing;
using Infrastructure;
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

        var pkeKeyPair = PkeGenerator.Generate(parameter, pkeSeed);

        Array.Clear(pkeSeed, 0, pkeSeed.Length);

        var hash = new SHA3_256().Digest(pkeKeyPair.EncryptionKey.FullBytes);

        return new KyberKEMKeyPair(
            new KyberEncapsulationKey(pkeKeyPair.EncryptionKey),
            new KyberDecapsulationKey(pkeKeyPair.DecryptionKey, pkeKeyPair.EncryptionKey, hash, randomSeed));
    }

    internal static class PkeGenerator
    {
        internal static KyberPKEKeyPair Generate(KyberParameter parameter, byte[] seed)
        {
            var sha512 = new SHA3_512();
            sha512.Update(seed);
            sha512.Update((byte)parameter.K);
            var seeds = sha512.Digest();

            Array.Clear(seed, 0, seed.Length);

            var nttSeed = new byte[32];
            var cbdSeed = new byte[32];
            Buffer.BlockCopy(seeds, 0, nttSeed, 0, 32);
            Buffer.BlockCopy(seeds, 32, cbdSeed, 0, 32);

            Array.Clear(seeds, 0, seeds.Length);

            var k = parameter.K;
            var matrix = new int[k][][];
            var secretVector = new int[k][];
            var noiseVector = new int[k][];

            for (var i = 0; i < k; i++)
            {
                matrix[i] = new int[k][];

                for (var j = 0; j < k; j++)
                {
                    matrix[i][j] = new int[KyberConstants.N];
                }
            }

            var decryptionKeyBytes = new byte[parameter.DecryptionKeyLength];

            for (var i = 0; i < k; i++)
            {
                for (var j = 0; j < k; j++)
                {
                    matrix[i][j] = Sampling.SampleNTT(Sampling.Xof(nttSeed, (byte)j, (byte)i));
                }

                secretVector[i] = Sampling.SamplePolyCBD(
                    parameter.Eta1,
                    Sampling.Prf(parameter.Eta1, cbdSeed, (byte)i));

                secretVector[i] = PolyMath.Ntt(secretVector[i]);
                Encoding.ByteEncodeInto(decryptionKeyBytes, i * KyberConstants.ENCODE_SIZE, secretVector[i], 12);

                noiseVector[i] = Sampling.SamplePolyCBD(
                    parameter.Eta1,
                    Sampling.Prf(parameter.Eta1, cbdSeed, (byte)(i + k)));

                noiseVector[i] = PolyMath.Ntt(noiseVector[i]);
            }

            Array.Clear(cbdSeed, 0, cbdSeed.Length);

            var systemVector = PolyMath.NttMatrixVectorDot(matrix, secretVector, false);
            systemVector = PolyMath.VectorAdd(systemVector, noiseVector);

            var encryptionKeyBytes = new byte[parameter.EncryptionKeyLength - 32];

            for (var i = 0; i < k; i++)
            {
                Encoding.ByteEncodeInto(encryptionKeyBytes, i * KyberConstants.ENCODE_SIZE, systemVector[i], 12);
            }

            return new KyberPKEKeyPair(
                new KyberEncryptionKey(parameter, encryptionKeyBytes, nttSeed),
                new KyberDecryptionKey(parameter, decryptionKeyBytes));
        }
    }
}