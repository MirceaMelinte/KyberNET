namespace KyberNET.Keys
{
    using System;
    using Constants;

    public sealed class KyberCipherText
    {
        public KyberParameter Parameter { get; }
        
        internal byte[] EncodedCoefficients { get; }
        internal byte[] EncodedTerms { get; }

        internal KyberCipherText(KyberParameter parameter, byte[] encodedCoefficients, byte[] encodedTerms)
        {
            Parameter = parameter;
            EncodedCoefficients = (byte[])encodedCoefficients.Clone();
            EncodedTerms = (byte[])encodedTerms.Clone();
        }

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