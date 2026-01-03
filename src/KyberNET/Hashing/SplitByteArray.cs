namespace KyberNET.Hashing
{
    internal sealed class SplitByteArray(byte[] a, byte[] b)
    {
        public byte[] A { get; set; } = a;

        public byte[] B { get; } = b;

        public int Size => A.Length + B.Length;
        public int LastIndex => A.Length + B.Length - 1;

        public byte this[int i]
        {
            get => (i < A.Length) ? A[i] : B[i - A.Length];
            set
            {
                if (i < A.Length)
                {
                    A[i] = value;
                }
                else
                {
                    B[i - A.Length] = value;
                }
            }
        }
    }
}