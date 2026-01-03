namespace KyberNET.Hashing
{
    using System;

    public class HashOutputStream
    {
        private KeccakParameter PARAMETER { get; }

        private readonly long[][] state;
        private readonly SplitByteArray stateBuffer;
        
        private readonly bool squeezable;
        private readonly int maxOutputLength; // enforced only when !squeezable
        
        private int used;
        private int totalOutputLength;

        private static bool IsSqueezable(KeccakParameter input) =>
            ReferenceEquals(input, KeccakParameter.SHAKE_128) || ReferenceEquals(input, KeccakParameter.SHAKE_256);

        internal HashOutputStream(
            KeccakParameter parameter,
            FlexiByte suffix,
            (byte[][] chunks, int lastChunkUsed) inputChunks,
            int maxOutputLength)
        {
            PARAMETER = parameter;
            state = KeccakHash.NewState();
            stateBuffer = new SplitByteArray(new byte[PARAMETER.BYTERATE], new byte[200 - PARAMETER.BYTERATE]);
            this.maxOutputLength = maxOutputLength;
            squeezable = IsSqueezable(parameter);

            KeccakHash.GenerateDirect(parameter, inputChunks, suffix, stateBuffer, state);

            stateBuffer.A = new byte[PARAMETER.BYTERATE];
            KeccakMath.DirectMatrixToBytes(state, stateBuffer);
        }

        internal HashOutputStream(KeccakParameter parameter, long[][] completedState, int maxOutputLength)
        {
            PARAMETER = parameter;
            state = completedState;
            stateBuffer = new SplitByteArray(new byte[PARAMETER.BYTERATE], new byte[200 - PARAMETER.BYTERATE]);
            KeccakMath.DirectMatrixToBytes(state, stateBuffer);
            this.maxOutputLength = maxOutputLength;
            squeezable = IsSqueezable(parameter);
        }

        private void EnforceLimit(int extra)
        {
            if (!squeezable && (totalOutputLength + extra > maxOutputLength))
            {
                throw new InvalidOperationException($"This parameter only supports a total output of {maxOutputLength} bytes. This function is not extendable");
            }
        }

        private void TrySqueeze()
        {
            if (used < stateBuffer.A.Length)
            {
                return;
            }
            
            KeccakMath.DirectPermute(state);
            KeccakMath.DirectMatrixToBytes(state, stateBuffer);
            
            used = 0;
        }

        public byte NextByte()
        {
            EnforceLimit(1);
            TrySqueeze();
            
            totalOutputLength++;
            
            return stateBuffer.A[used++];
        }

        public byte[] NextBytes(int length)
        {
            EnforceLimit(length);
            
            var outArr = new byte[length];
            var offset = 0;
            
            while (offset < length)
            {
                TrySqueeze();
                var take = Math.Min(stateBuffer.A.Length - used, length - offset);
                
                Buffer.BlockCopy(stateBuffer.A, used, outArr, offset, take);
                
                used += take;
                offset += take;
                totalOutputLength += take;
            }
            
            return outArr;
        }

        public void NextBytes(byte[] destination)
        {
            EnforceLimit(destination.Length);
            
            var offset = 0;
            
            while (offset < destination.Length)
            {
                TrySqueeze();
                var take = Math.Min(stateBuffer.A.Length - used, destination.Length - offset);
                
                Buffer.BlockCopy(stateBuffer.A, used, destination, offset, take);
                
                used += take;
                offset += take;
                totalOutputLength += take;
            }
        }

        public bool HasNext() => squeezable || totalOutputLength < maxOutputLength;
    }
}