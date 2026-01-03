namespace KyberNET.Hashing
{
    using System;
    using System.Collections.Generic;
    using KyberNET.Exceptions;

    internal sealed class UniversalDigestor
    {
        private readonly int initialCapacity;
        private readonly List<byte[]> storage = [];
        private byte[] buffer;
        private int position;

        public UniversalDigestor(int initialCapacity)
        {
            if (initialCapacity <= 0)
            {
                throw new ArgumentException("initialCapacity must be greater than zero");
            }
            
            this.initialCapacity = initialCapacity;
            buffer = new byte[this.initialCapacity];
            position = 0;
        }

        private void WillItFit(long size)
        {
            var expected = position + (long)storage.Count * initialCapacity + size;
            
            if (expected is > int.MaxValue or < 0)
            {
                throw new DigestTooLargeException(expected);
            }
        }

        private void AllocateIfRequired()
        {
            if (position != buffer.Length)
            {
                return;
            }
            
            storage.Add(buffer);
            buffer = new byte[initialCapacity];
            position = 0;
        }

        public void DigestSingle(byte b)
        {
            WillItFit(1);
            buffer[position++] = b;
            AllocateIfRequired();
        }

        public void Digest(byte[] bytes, int offset = 0, int length = -1)
        {
            if (length < 0)
            {
                length = bytes.Length - offset;
            }

            if (offset > bytes.Length)
            {
                throw new IndexOutOfRangeException("Offset exceeds bytes length");
            }

            if (offset + length > bytes.Length)
            {
                throw new IndexOutOfRangeException("Offset + length exceeds bytes length");
            }

            if (length < 0 || offset < 0)
            {
                throw new IndexOutOfRangeException();
            }

            WillItFit(length);

            var inputIndex = offset;
            var end = offset + length;
            
            while (inputIndex < end)
            {
                var toCopy = Math.Min(end - inputIndex, buffer.Length - position);
                Buffer.BlockCopy(bytes, inputIndex, buffer, position, toCopy);
                
                inputIndex += toCopy;
                position += toCopy;
                
                AllocateIfRequired();
            }
        }

        public (byte[][] chunks, int lastChunkUsed) ExtractChunksAndReset()
        {
            try
            {
                storage.Add(buffer);
                var table = storage.ToArray();
                var lastPosition = position;

                storage.Clear();
                buffer = new byte[initialCapacity];
                position = 0;

                return (table, lastPosition);
            }
            catch
            {
                storage.Clear();
                buffer = new byte[initialCapacity];
                position = 0;
                
                throw;
            }
        }
    }
}