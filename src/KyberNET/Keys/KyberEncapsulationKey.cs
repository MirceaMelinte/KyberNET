namespace KyberNET.Keys
{
    using Constants;
    using Internal;
    
    public sealed class KyberEncapsulationKey
        : IKyberKEMKey
    {
        internal KyberEncryptionKey Key { get; }
        
        IKyberPKEKey IKyberKEMKey.Key => Key;

        internal KyberEncapsulationKey(KyberEncryptionKey key)
        {
            Key = key;
        }

        public byte[] FullBytes => Key.FullBytes;
        
        public KyberEncapsulationResult Encapsulate(IRandomProvider? randomProvider = null)
        {
            var plainText = new byte[KyberConstants.N_BYTES];
            
            var rng = randomProvider ?? DefaultRandomProvider.Instance;
            rng.FillWithRandom(plainText);
            
            return KyberAgreement.Encapsulate(this, plainText);
        }

        public static KyberEncapsulationKey FromBytes(byte[] bytes) => new(KyberEncryptionKey.FromBytes(bytes));
    }
}