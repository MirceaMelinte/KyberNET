namespace KyberNET.Internal;

using Constants;
using Exceptions;
using Hashing;
using Infrastructure;
using Keys;

internal static class KyberAgreement
{
    private static KyberCipherText ToCipherText(KyberEncryptionKey encryptionKey, byte[] plainText, byte[] randomness)
    {
        var parameter = encryptionKey.Parameter;

        var nttKeyVector = new int[parameter.K][];
        var matrix = new int[parameter.K][][];
        var randomnessVector = new int[parameter.K][];
        var noiseVector = new int[parameter.K][];

        var constantTerm = new int[KyberConstants.N];

        for (var i = 0; i < parameter.K; i++)
        {
            nttKeyVector[i] = Encoding.FastByteDecode(
                encryptionKey.KeyBytes,
                12,
                i * KyberConstants.ENCODE_SIZE,
                KyberConstants.ENCODE_SIZE);

            Encoding.VectorToMontVector(nttKeyVector[i]);

            randomnessVector[i] = Sampling.SamplePolyCBD(
                parameter.Eta1,
                Sampling.Prf(parameter.Eta1, randomness, (byte)i));
            
            PolyMath.Ntt(randomnessVector[i]);

            PolyMath.MultiplyNttsAddInto(constantTerm, randomnessVector[i], nttKeyVector[i]);

            noiseVector[i] = Sampling.SamplePolyCBD(
                parameter.Eta2,
                Sampling.Prf(parameter.Eta2, randomness, (byte)(i + parameter.K)));

            matrix[i] = new int[parameter.K][];

            for (var j = 0; j < parameter.K; j++)
            {
                matrix[i][j] = Sampling.SampleNTT(Sampling.Xof(encryptionKey.NttSeed, (byte)j, (byte)i));
            }
        }

        PolyMath.InverseNtt(constantTerm);

        var noiseTerm = Sampling.SamplePolyCBD(
            parameter.Eta2,
            Sampling.Prf(parameter.Eta2, randomness, (byte)(parameter.K * 2)));

        PolyMath.VectorAdd(constantTerm, noiseTerm);
        
        Array.Clear(noiseTerm, 0, noiseTerm.Length);

        var mu = Encoding.ExpandMu(plainText);
        
        PolyMath.VectorAdd(constantTerm, mu);
        
        Array.Clear(mu, 0, mu.Length);

        var encodedTerms = new byte[KyberConstants.N_BYTES * parameter.Dv];
        Encoding.CompressAndEncodeInto(encodedTerms, 0, constantTerm, parameter.Dv);

        var coefficients = PolyMath.NttMatrixVectorDot(matrix, randomnessVector, true);
        var encodedCoefficients = new byte[KyberConstants.N_BYTES * (parameter.Du * parameter.K)];

        for (var i = 0; i < parameter.K; i++)
        {
            PolyMath.InverseNtt(coefficients[i]);
            PolyMath.VectorAdd(coefficients[i], noiseVector[i]);

            Encoding.CompressAndEncodeInto(
                encodedCoefficients,
                i * KyberConstants.N_BYTES * parameter.Du,
                coefficients[i],
                parameter.Du);

            Array.Clear(noiseVector[i], 0, noiseVector[i].Length);
            Array.Clear(randomnessVector[i], 0, randomnessVector[i].Length);
        }

        return new KyberCipherText(parameter, encodedCoefficients, encodedTerms);
    }

    internal static byte[] FromCipherText(KyberDecryptionKey decryptionKey, KyberCipherText cipherText)
    {
        var parameter = cipherText.Parameter;

        var secretVector = Encoding.FastByteDecode(decryptionKey.KeyBytes, 12);

        Encoding.VectorToMontVector(secretVector);

        var constantTerms = Encoding.FastByteDecode(cipherText.EncodedTerms, parameter.Dv);

        Encoding.Decompress(constantTerms, parameter.Dv);
        Encoding.VectorToMontVector(constantTerms);

        var subtraction = new int[KyberConstants.N];

        for (var i = 0; i < parameter.K; i++)
        {
            var coefficients = Encoding.FastByteDecode(
                cipherText.EncodedCoefficients,
                parameter.Du,
                i * KyberConstants.N_BYTES * parameter.Du,
                KyberConstants.N_BYTES * parameter.Du);

            Encoding.Decompress(coefficients, parameter.Du);
            Encoding.VectorToMontVector(coefficients);

            PolyMath.Ntt(coefficients);

            PolyMath.MultiplyNttsInto(subtraction, secretVector, coefficients, i * KyberConstants.N);
            PolyMath.InverseNtt(subtraction);

            for (var j = 0; j < KyberConstants.N; j++)
            {
                constantTerms[j] -= subtraction[j];
            }
        }

        Array.Clear(secretVector, 0, secretVector.Length);

        var result = new byte[KyberConstants.N_BYTES];

        Encoding.CompressAndEncodeInto(result, 0, constantTerms, 1);

        return result;
    }

    internal static KyberEncapsulationResult Encapsulate(KyberEncapsulationKey encapsulationKey, byte[] plainText)
    {
        if (Subtle.IsAllZero(plainText))
        {
            throw new RandomBitGenerationException();
        }

        var encapsulationKeyHash = new SHA3_256().Digest(encapsulationKey.Key.FullBytes);

        var sha512 = new SHA3_512();
        sha512.Update(plainText);
        sha512.Update(encapsulationKeyHash);
        var sharedKeyAndRandomness = sha512.Digest();

        var cipherText = ToCipherText(
            encapsulationKey.Key,
            plainText,
            sharedKeyAndRandomness[KyberConstants.SECRET_KEY_LENGTH..]);

        Array.Clear(plainText, 0, plainText.Length);

        var sharedKey = sharedKeyAndRandomness[..KyberConstants.SECRET_KEY_LENGTH];
        Array.Clear(sharedKeyAndRandomness, 0, sharedKeyAndRandomness.Length);

        return new KyberEncapsulationResult(sharedKey, cipherText);
    }

    internal static byte[] Decapsulate(KyberDecapsulationKey decapsulationKey, KyberCipherText cipherText)
    {
        var recoveredPlainText = FromCipherText(decapsulationKey.Key, cipherText);

        var sha512 = new SHA3_512();
        sha512.Update(recoveredPlainText);
        sha512.Update(decapsulationKey.Hash);
        var decapsulationHash = sha512.Digest();

        var shake = new SHAKE256();
        shake.Update(decapsulationKey.RandomSeed);
        shake.Update(cipherText.FullBytes);
        var secretKeyRejection = shake.Digest();

        var secretKeyCandidate = decapsulationHash[..KyberConstants.SECRET_KEY_LENGTH];

        var regeneratedCipherText = ToCipherText(
            decapsulationKey.EncryptionKey,
            recoveredPlainText,
            decapsulationHash[KyberConstants.SECRET_KEY_LENGTH..]);

        Array.Clear(recoveredPlainText, 0, recoveredPlainText.Length);
        Array.Clear(decapsulationHash, 0, decapsulationHash.Length);

        var condition = Subtle.Compare(cipherText.FullBytes, regeneratedCipherText.FullBytes);
        secretKeyCandidate = Subtle.Select(condition, secretKeyCandidate, secretKeyRejection);

        Array.Clear(secretKeyRejection, 0, secretKeyRejection.Length);

        return secretKeyCandidate;
    }
}
