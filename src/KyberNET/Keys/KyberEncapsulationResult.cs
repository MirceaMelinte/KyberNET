namespace KyberNET.Keys
{
    public sealed class KyberEncapsulationResult
    {
        private readonly byte[] sharedSecretKey;

        public byte[] SharedSecretKey => (byte[])sharedSecretKey.Clone();
        public KyberCipherText CipherText { get; }

        internal KyberEncapsulationResult(byte[] sharedSecretKey, KyberCipherText cipherText)
        {
            this.sharedSecretKey = (byte[])sharedSecretKey.Clone();
            CipherText = cipherText;
        }
    }
}