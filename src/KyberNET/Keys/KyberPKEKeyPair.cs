namespace KyberNET.Keys;

internal sealed class KyberPKEKeyPair(KyberEncryptionKey encryptionKey, KyberDecryptionKey decryptionKey)
{
    public KyberEncryptionKey EncryptionKey { get; } = encryptionKey;
    public KyberDecryptionKey DecryptionKey { get; } = decryptionKey;
}
