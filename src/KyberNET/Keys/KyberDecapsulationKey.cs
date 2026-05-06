namespace KyberNET.Keys
{
    using System;
    using System.Linq;
    using Constants;
    using Exceptions;
    using Hashing;

    public sealed class KyberDecapsulationKey
    {
        internal KyberDecryptionKey Key { get; }
        internal KyberEncryptionKey EncryptionKey { get; }
        internal byte[] Hash { get; }
        internal byte[] RandomSeed { get; }
        
        public KyberParameter Parameter { get; }

        internal KyberDecapsulationKey(KyberDecryptionKey key, KyberEncryptionKey encryptionKey, byte[] hash, byte[] randomSeed)
        {
            Key = key;
            EncryptionKey = encryptionKey;
            Hash = (byte[])hash.Clone();
            RandomSeed = (byte[])randomSeed.Clone();
            Parameter = key.Parameter;

            var encapsulationKeyHash = new SHA3_256().Digest(encryptionKey.FullBytes);

            if (!encapsulationKeyHash.SequenceEqual(hash))
            {
                throw new InvalidKyberKeyException("Hash check failed! Invalid decapsulation key");
            }
        }

        public byte[] FullBytes
        {
            get
            {
                var output = new byte[Parameter.DecapsulationKeyLength];
                var offset = 0;

                Buffer.BlockCopy(Key.KeyBytes, 0, output, offset, Key.KeyBytes.Length);
                offset += Key.KeyBytes.Length;

                var encryptionKeyBytes = EncryptionKey.FullBytes;
                Buffer.BlockCopy(encryptionKeyBytes, 0, output, offset, encryptionKeyBytes.Length);
                offset += encryptionKeyBytes.Length;

                Buffer.BlockCopy(Hash, 0, output, offset, Hash.Length);
                offset += Hash.Length;

                Buffer.BlockCopy(RandomSeed, 0, output, offset, RandomSeed.Length);

                return output;
            }
        }

        public static KyberDecapsulationKey FromBytes(byte[] bytes)
        {
            var parameter = KyberParameter.FindByDecapsulationKeySize(bytes.Length);

            var decryptionKeyBytes = new byte[parameter.DecryptionKeyLength];
            Buffer.BlockCopy(bytes, 0, decryptionKeyBytes, 0, decryptionKeyBytes.Length);
            var decryptionKey = KyberDecryptionKey.FromBytes(decryptionKeyBytes);
            
            var encryptionKeyBytes = new byte[parameter.EncryptionKeyLength];
            Buffer.BlockCopy(bytes, parameter.DecryptionKeyLength, encryptionKeyBytes, 0, encryptionKeyBytes.Length);
            var encryptionKey = KyberEncryptionKey.FromBytes(encryptionKeyBytes);

            var hash = new byte[KyberConstants.N_BYTES];
            Buffer.BlockCopy(bytes, bytes.Length - (2 * KyberConstants.N_BYTES), hash, 0, KyberConstants.N_BYTES);

            var randomSeed = new byte[KyberConstants.N_BYTES];
            Buffer.BlockCopy(bytes, bytes.Length - KyberConstants.N_BYTES, randomSeed, 0, KyberConstants.N_BYTES);

            return new KyberDecapsulationKey(decryptionKey, encryptionKey, hash, randomSeed);
        }
    }
}