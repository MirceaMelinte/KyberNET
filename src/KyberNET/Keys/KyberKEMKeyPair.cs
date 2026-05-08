namespace KyberNET.Keys
{
    /// <summary>
    /// An ML-KEM key pair consisting of an encapsulation key and a decapsulation key
    /// </summary>
    public sealed class KyberKEMKeyPair
    {
        /// <summary>
        /// The public encapsulation key
        /// </summary>
        public KyberEncapsulationKey EncapsulationKey { get; }

        /// <summary>
        /// The private decapsulation key
        /// </summary>
        public KyberDecapsulationKey DecapsulationKey { get; }

        internal KyberKEMKeyPair(KyberEncapsulationKey encapsulationKey, KyberDecapsulationKey decapsulationKey)
        {
            EncapsulationKey = encapsulationKey;
            DecapsulationKey = decapsulationKey;
        }
    }
}