namespace KyberNET.Keys
{
    public sealed class KyberKEMKeyPair
    {
        public KyberEncapsulationKey EncapsulationKey { get; }
        public KyberDecapsulationKey DecapsulationKey { get; }

        internal KyberKEMKeyPair(KyberEncapsulationKey encapsulationKey, KyberDecapsulationKey decapsulationKey)
        {
            EncapsulationKey = encapsulationKey;
            DecapsulationKey = decapsulationKey;
        }
    }
}