namespace KyberNET.Keys;

internal sealed class KyberPKEKeyPair(KyberEncryptionKey encryptionKey, KyberDecryptionKey decryptionKey)
    : IDisposable
{
    private bool disposed;

    public KyberEncryptionKey EncryptionKey { get; } = encryptionKey;
    public KyberDecryptionKey DecryptionKey { get; } = decryptionKey;

    public void Dispose()
    {
        if (!disposed)
        {
            DecryptionKey.Dispose();
            
            disposed = true;
        }
    }
}
