namespace KyberNET.Keys
{
    public sealed class KyberPKEKeyPair
    {
        public KyberEncryptionKey EncryptionKey { get; }
        public KyberDecryptionKey DecryptionKey { get; }

        internal KyberPKEKeyPair(KyberEncryptionKey encryptionKey, KyberDecryptionKey decryptionKey)
        {
            EncryptionKey = encryptionKey;
            DecryptionKey = decryptionKey;
        }
    }
}