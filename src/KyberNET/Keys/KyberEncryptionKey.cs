namespace KyberNET.Keys
{
    using System;
    using Constants;
    using Exceptions;
    using Infrastructure;

    public sealed class KyberEncryptionKey
    {
        public KyberParameter Parameter { get; }
        
        internal byte[] KeyBytes { get; }
        internal byte[] NttSeed { get; }

        internal KyberEncryptionKey(KyberParameter parameter, byte[] keyBytes, byte[] nttSeed)
        {
            Parameter = parameter;
            KeyBytes = (byte[])keyBytes.Clone();
            NttSeed = (byte[])nttSeed.Clone();

            var coefficients = Encoding.FastByteDecode(KeyBytes, 12);

            for (var i = 0; i < coefficients.Length; i++)
            {
                if (!ModMath.IsModuloOfQ(coefficients[i]))
                {
                    throw new InvalidKyberKeyException($"Not modulus of {KyberConstants.Q}");
                }
            }
        }

        public byte[] FullBytes
        {
            get
            {
                var output = new byte[Parameter.EncapsulationKeyLength];
                
                Buffer.BlockCopy(KeyBytes, 0, output, 0, KeyBytes.Length);
                Buffer.BlockCopy(NttSeed, 0, output, KeyBytes.Length, NttSeed.Length);
                
                return output;
            }
        }

        public static KyberEncryptionKey FromBytes(byte[] bytes)
        {
            var keyLength = bytes.Length - KyberConstants.N_BYTES;
            var keyBytes = new byte[keyLength];
            var nttSeed = new byte[KyberConstants.N_BYTES];
            
            Buffer.BlockCopy(bytes, 0, keyBytes, 0, keyLength);
            Buffer.BlockCopy(bytes, keyLength, nttSeed, 0, KyberConstants.N_BYTES);
            
            return new KyberEncryptionKey(KyberParameter.FindByEncryptionKeySize(bytes.Length), keyBytes, nttSeed);
        }
    }
}