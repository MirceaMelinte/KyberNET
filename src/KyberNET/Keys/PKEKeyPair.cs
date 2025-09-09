namespace KyberNET.Keys
{
    public class PKEKeyPair
    {
        public EncryptionKey EncryptionKey { get; set; }

        public DecryptionKey DecryptionKey { get; set; }

        internal PKEKeyPair(EncryptionKey encryptionKey, DecryptionKey decryptionKey)
        {
            EncryptionKey = encryptionKey;
            DecryptionKey = decryptionKey;
        }
    }
}