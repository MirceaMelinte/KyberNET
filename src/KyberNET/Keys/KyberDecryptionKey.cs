namespace KyberNET.Keys
{
    using Constants;
    using Exceptions;
    using Infrastructure;

    public sealed class KyberDecryptionKey
    {
        public KyberParameter Parameter { get; }
        
        internal byte[] KeyBytes { get; }

        internal KyberDecryptionKey(KyberParameter parameter, byte[] keyBytes)
        {
            Parameter = parameter;
            KeyBytes = (byte[])keyBytes.Clone();

            var coefficients = Encoding.FastByteDecode(KeyBytes, 12);

            for (var i = 0; i < coefficients.Length; i++)
            {
                if (!ModMath.IsModuloOfQ(coefficients[i]))
                {
                    throw new InvalidKyberKeyException($"Not modulus of {KyberConstants.Q}");
                }
            }
        }

        public byte[] FullBytes => (byte[])KeyBytes.Clone();

        public static KyberDecryptionKey FromBytes(byte[] bytes)
            => new(KyberParameter.FindByDecryptionKeySize(bytes.Length), bytes);
    }
}