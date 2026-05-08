namespace KyberNET.Keys
{
    using System;
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
                
                Buffer.BlockCopy(EncodedCoefficients, 0, output, 0, EncodedCoefficients.Length);
                Buffer.BlockCopy(EncodedTerms, 0, output, EncodedCoefficients.Length, EncodedTerms.Length);
                
                return output;
            }
        }

        /// <summary>
        /// Deserializes a ciphertext from byte representation
        /// </summary>
        public static KyberCipherText FromBytes(byte[] bytes)
        {
            var parameter = KyberParameter.FindByCipherTextSize(bytes.Length);
            var encodedCoefficientsSize = KyberConstants.N_BYTES * (parameter.Du * parameter.K);

            var coefficients = new byte[encodedCoefficientsSize];
            var terms = new byte[bytes.Length - encodedCoefficientsSize];
            
            Buffer.BlockCopy(bytes, 0, coefficients, 0, encodedCoefficientsSize);
            Buffer.BlockCopy(bytes, encodedCoefficientsSize, terms, 0, terms.Length);

            return new KyberCipherText(parameter, coefficients, terms);
        }
    }
}