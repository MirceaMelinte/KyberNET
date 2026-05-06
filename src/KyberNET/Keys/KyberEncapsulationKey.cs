namespace KyberNET.Keys
{
    public sealed class KyberEncapsulationKey
    {
        internal KyberEncryptionKey Key { get; }

        internal KyberEncapsulationKey(KyberEncryptionKey key)
        {
            Key = key;
        }

        public byte[] FullBytes => Key.FullBytes;

        public static KyberEncapsulationKey FromBytes(byte[] bytes) => new(KyberEncryptionKey.FromBytes(bytes));
    }
}