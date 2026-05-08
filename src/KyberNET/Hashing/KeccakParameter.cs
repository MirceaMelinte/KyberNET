namespace KyberNET.Hashing
{
    internal sealed class KeccakParameter
    {   
        private KeccakParameter(int minLength, int maxLength, int bitrate, int capacity, FlexiByte suffix)
        {
            MIN_LENGTH = minLength;
            MAX_LENGTH = maxLength;
            BITRATE = bitrate;
            CAPACITY = capacity;
            SUFFIX = suffix;
            BYTERATE = BITRATE >> 3;
        }
        
        public int BITRATE { get; }
        
        public int MIN_LENGTH { get; }
        
        public int MAX_LENGTH { get; }

        public int CAPACITY { get; }

        public FlexiByte SUFFIX { get; }

        public int BYTERATE { get; }

        public static readonly KeccakParameter SHAKE_128 = new(
            minLength: 128,
            maxLength: 0,
            bitrate: 1344,
            capacity: 256,
            suffix: new FlexiByte(0b1111, 3)
        );

        public static readonly KeccakParameter SHAKE_256 = new(
            minLength: 256,
            maxLength: 0,
            bitrate: 1088,
            capacity: 512,
            suffix: new FlexiByte(0b1111, 3)
        );
        
        public static readonly KeccakParameter SHA3_256 = new(
            minLength: 256,
            maxLength: 256,
            bitrate: 1088,
            capacity: 512,
            suffix: new FlexiByte(0b10, 1)
        );
        
        public static readonly KeccakParameter SHA3_512 = new(
            minLength: 512,
            maxLength: 512,
            bitrate: 576,
            capacity: 1024,
            suffix: new FlexiByte(0b10, 1)
        );
    }
}