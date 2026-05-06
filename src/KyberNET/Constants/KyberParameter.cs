namespace KyberNET.Constants
{
    using Exceptions;

    public sealed class KyberParameter
    {
        public static readonly KyberParameter MlKem512 = new(2, 3, 2, 10, 4);
        public static readonly KyberParameter MlKem768 = new(3, 2, 2, 10, 4);
        public static readonly KyberParameter MlKem1024 = new(4, 2, 2, 11, 5);

        private static readonly KyberParameter[] All = [MlKem512, MlKem768, MlKem1024];

        public int K { get; }
        
        public int Eta1 { get; }
        public int Eta2 { get; }
        
        public int Du { get; }
        public int Dv { get; }

        public int CiphertextLength { get; }
        
        public int DecryptionKeyLength { get; }
        public int EncryptionKeyLength { get; }
        
        public int EncapsulationKeyLength { get; }
        public int DecapsulationKeyLength { get; }

        private KyberParameter(int k, int eta1, int eta2, int du, int dv)
        {
            K = k;
            
            Eta1 = eta1;
            Eta2 = eta2;
            
            Du = du;
            Dv = dv;

            CiphertextLength = KyberConstants.N_BYTES * ((Du * K) + Dv);
            
            DecryptionKeyLength = KyberConstants.ENCODE_SIZE * K;
            EncryptionKeyLength = DecryptionKeyLength + KyberConstants.N_BYTES;
            
            EncapsulationKeyLength = EncryptionKeyLength;
            DecapsulationKeyLength = EncapsulationKeyLength + DecryptionKeyLength + (2 * KyberConstants.N_BYTES);
        }

        public static KyberParameter FindByCipherTextSize(int length)
        {
            foreach (var @param in All)
            {
                if (@param.CiphertextLength == length)
                {
                    return @param;
                }
            }

            throw new UnsupportedKyberVariantException("Cipher Text byte length is either bigger or smaller than expected");
        }

        public static KyberParameter FindByEncryptionKeySize(int length)
        {
            foreach (var @param in All)
            {
                if (@param.EncapsulationKeyLength == length)
                {
                    return @param;
                }
            }

            throw new UnsupportedKyberVariantException("Encryption Key byte length is either bigger or smaller than expected");
        }

        public static KyberParameter FindByEncapsulationKeySize(int length)
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

        public static KyberParameter FindByDecryptionKeySize(int length)
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

        public static KyberParameter FindByDecapsulationKeySize(int length)
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
}