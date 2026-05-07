namespace KyberNET.Internal
{
    using System;
    using System.Linq;
    using Constants;
    using Hashing;
    using Infrastructure;
    using Keys;
    using Exceptions;

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
                randomnessVector[i] = PolyMath.Ntt(randomnessVector[i]);

                constantTerm = PolyMath.VectorAdd(
                    constantTerm,
                    PolyMath.MultiplyNtts(randomnessVector[i], nttKeyVector[i]));

                noiseVector[i] = Sampling.SamplePolyCBD(
                    parameter.Eta2,
                    Sampling.Prf(parameter.Eta2, randomness, (byte)(i + parameter.K)));

                matrix[i] = new int[parameter.K][];

                for (var j = 0; j < parameter.K; j++)
                {
                    matrix[i][j] = Sampling.SampleNTT(Sampling.Xof(encryptionKey.NttSeed, (byte)j, (byte)i));
                }
            }

            constantTerm = PolyMath.InverseNtt(constantTerm);

            var noiseTerm = Sampling.SamplePolyCBD(
                parameter.Eta2,
                Sampling.Prf(parameter.Eta2, randomness, (byte)(parameter.K * 2)));

            constantTerm = PolyMath.VectorAdd(constantTerm, noiseTerm);
            Array.Clear(noiseTerm);

            var muse = Encoding.ExpandMuse(plainText);
            constantTerm = PolyMath.VectorAdd(constantTerm, muse);
            Array.Clear(muse);

            var encodedTerms = new byte[KyberConstants.N_BYTES * parameter.Dv];
            Encoding.CompressAndEncodeInto(encodedTerms, 0, constantTerm, parameter.Dv);

            var coefficients = PolyMath.NttMatrixVectorDot(matrix, randomnessVector, true);
            var encodedCoefficients = new byte[KyberConstants.N_BYTES * (parameter.Du * parameter.K)];

            for (var i = 0; i < parameter.K; i++)
            {
                coefficients[i] = PolyMath.InverseNtt(coefficients[i]);
                coefficients[i] = PolyMath.VectorAdd(coefficients[i], noiseVector[i]);
                
                Encoding.CompressAndEncodeInto(
                    encodedCoefficients,
                    i * KyberConstants.N_BYTES * parameter.Du,
                    coefficients[i],
                    parameter.Du);

                Array.Clear(noiseVector[i]);
                Array.Clear(randomnessVector[i]);
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

            for (var i = 0; i < parameter.K; i++)
            {
                var coefficients = Encoding.FastByteDecode(
                    cipherText.EncodedCoefficients,
                    parameter.Du,
                    i * KyberConstants.N_BYTES * parameter.Du,
                    KyberConstants.N_BYTES * parameter.Du);
                
                Encoding.Decompress(coefficients, parameter.Du);
                Encoding.VectorToMontVector(coefficients);
                
                coefficients = PolyMath.Ntt(coefficients);

                var subtraction = PolyMath.MultiplyNtts(secretVector, coefficients, i * KyberConstants.N);
                subtraction = PolyMath.InverseNtt(subtraction);

                for (var j = 0; j < KyberConstants.N; j++)
                {
                    constantTerms[j] -= subtraction[j];
                }
            }

            var result = new byte[KyberConstants.N_BYTES];
            
            Encoding.CompressAndEncodeInto(result, 0, constantTerms, 1);
            
            return result;
        }

        internal static KyberEncapsulationResult Encapsulate(KyberEncapsulationKey encapsulationKey, byte[] plainText)
        {
            if (plainText.All(b => b == 0))
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

            Array.Clear(plainText);

            return new KyberEncapsulationResult(sharedKeyAndRandomness[..KyberConstants.SECRET_KEY_LENGTH], cipherText);
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

            Array.Clear(recoveredPlainText);
            Array.Clear(decapsulationHash);

            if (!cipherText.FullBytes.SequenceEqual(regeneratedCipherText.FullBytes))
            {
                secretKeyCandidate = secretKeyRejection;
            }

            return secretKeyCandidate;
        }
    }
}