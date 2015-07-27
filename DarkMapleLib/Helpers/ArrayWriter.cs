/*!
Copyright 2014 Yaminike

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System.Text;

namespace DarkMapleLib.Helpers
{
    /// <summary>
    ///     Class to handle writing data to an byte array
    /// </summary>
    public class ArrayWriter
    {
        /// <summary>
        ///     Creates a new instance of a ArrayWriter
        /// </summary>
        /// <param name="initialBufferSize">Sets the initial size of the buffer</param>
        public ArrayWriter(int initialBufferSize = 0x50)
        {
            Buffer = new byte[initialBufferSize];
        }

        /// <summary>
        ///     Buffer holding the packet data
        /// </summary>
        private byte[] Buffer { get; set; }

        /// <summary>
        ///     Length of the packet
        /// </summary>
        public int Length { get; private set; }

        /// <summary>
        ///     The position to start reading on
        /// </summary>
        public int Position { get; set; }

        /// <summary>
        ///     Prevents the buffer being to small
        /// </summary>
        private void EnsureCapacity(int length)
        {
            if (Position + length < Buffer.Length) return; //Return as quikly as posible
            var newBuffer = new byte[Buffer.Length + 0x50];
            System.Buffer.BlockCopy(Buffer, 0, newBuffer, 0, Buffer.Length);
            Buffer = newBuffer;
            EnsureCapacity(length);
        }

        /// <summary>
        ///     Writes bytes to the buffer
        /// </summary>
        public unsafe void WriteBytes(byte[] bytes)
        {
            var length = bytes.Length;
            EnsureCapacity(length);

            fixed (byte* pBuffer = Buffer)
            {
                for (var i = 0; i < length; i++)
                    *(pBuffer + Position + i) = bytes[i];
            }

            Length += length;
            Position += length;
        }

        /// <summary>
        ///     Sets bytes in the buffer
        /// </summary>
        public unsafe void SetBytes(byte[] bytes, int position)
        {
            fixed (byte* pBuffer = Buffer)
            {
                for (var i = 0; i < bytes.Length; i++)
                    *(pBuffer + position + i) = bytes[i];
            }
        }

        /// <summary>
        ///     Writes a bool to the buffer
        /// </summary>
        public void WriteBool(bool value)
        {
            WriteByte((byte) (value ? 1 : 0));
        }

        /// <summary>
        ///     Sets a bool in the buffer
        /// </summary>
        public void SetBool(bool value, int position)
        {
            SetByte((byte) (value ? 1 : 0), position);
        }

        /// <summary>
        ///     Writes a signed byte to the buffer
        /// </summary>
        public unsafe void WriteSByte(sbyte value)
        {
            var length = 1;
            EnsureCapacity(length);

            fixed (byte* pBuffer = Buffer)
                *(sbyte*) (pBuffer + Position) = value;

            Length += length;
            Position += length;
        }

        /// <summary>
        ///     Sets a signed byte in the buffer
        /// </summary>
        public unsafe void SetSByte(sbyte value, int position)
        {
            fixed (byte* pBuffer = Buffer)
                *(sbyte*) (pBuffer + position) = value;
        }

        /// <summary>
        ///     Writes a unsigned byte to the buffer
        /// </summary>
        public unsafe void WriteByte(byte value)
        {
            var length = 1;
            EnsureCapacity(length);

            fixed (byte* pBuffer = Buffer)
                *(pBuffer + Position) = value;

            Length += length;
            Position += length;
        }

        /// <summary>
        ///     Sets a unsigned byte in the buffer
        /// </summary>
        public unsafe void SetByte(byte value, int position)
        {
            fixed (byte* pBuffer = Buffer)
                *(pBuffer + position) = value;
        }

        /// <summary>
        ///     Writes a signed short to the buffer
        /// </summary>
        public unsafe void WriteShort(short value)
        {
            var length = 2;
            EnsureCapacity(length);

            fixed (byte* pBuffer = Buffer)
                *(short*) (pBuffer + Position) = value;

            Length += length;
            Position += length;
        }

        /// <summary>
        ///     Sets a signed short in the buffer
        /// </summary>
        public unsafe void SetShort(short value, int position)
        {
            fixed (byte* pBuffer = Buffer)
                *(short*) (pBuffer + position) = value;
        }

        /// <summary>
        ///     Writes a unsigned short to the buffer
        /// </summary>
        public unsafe void WriteUShort(ushort value)
        {
            var length = 2;
            EnsureCapacity(length);

            fixed (byte* pBuffer = Buffer)
                *(ushort*) (pBuffer + Position) = value;

            Length += length;
            Position += length;
        }

        /// <summary>
        ///     Sets a unsigned short in the buffer
        /// </summary>
        public unsafe void SetUShort(ushort value, int position)
        {
            fixed (byte* pBuffer = Buffer)
                *(ushort*) (pBuffer + position) = value;
        }

        /// <summary>
        ///     Writes a signed int to the buffer
        /// </summary>
        public unsafe void WriteInt(int value)
        {
            var length = 4;
            EnsureCapacity(length);

            fixed (byte* pBuffer = Buffer)
                *(int*) (pBuffer + Position) = value;

            Length += length;
            Position += length;
        }

        /// <summary>
        ///     Sets a signed int in the buffer
        /// </summary>
        public unsafe void SetInt(int value, int position)
        {
            fixed (byte* pBuffer = Buffer)
                *(int*) (pBuffer + position) = value;
        }

        /// <summary>
        ///     Writes a unsigned int to the buffer
        /// </summary>
        public unsafe void WriteUInt(uint value)
        {
            var length = 4;
            EnsureCapacity(length);

            fixed (byte* pBuffer = Buffer)
                *(uint*) (pBuffer + Position) = value;

            Length += length;
            Position += length;
        }

        /// <summary>
        ///     Sets a unsigned int in the buffer
        /// </summary>
        public unsafe void SetUInt(uint value, int position)
        {
            fixed (byte* pBuffer = Buffer)
                *(uint*) (pBuffer + position) = value;
        }

        /// <summary>
        ///     Writes a signed long to the buffer
        /// </summary>
        public unsafe void WriteLong(long value)
        {
            var length = 8;
            EnsureCapacity(length);

            fixed (byte* pBuffer = Buffer)
                *(long*) (pBuffer + Position) = value;

            Length += length;
            Position += length;
        }

        /// <summary>
        ///     Sets a signed long in the buffer
        /// </summary>
        public unsafe void SetLong(long value, int position)
        {
            fixed (byte* pBuffer = Buffer)
                *(long*) (pBuffer + position) = value;
        }

        /// <summary>
        ///     Writes a unsigned long to the buffer
        /// </summary>
        public unsafe void WriteULong(ulong value)
        {
            var length = 8;
            EnsureCapacity(length);

            fixed (byte* pBuffer = Buffer)
                *(ulong*) (pBuffer + Position) = value;

            Length += length;
            Position += length;
        }

        /// <summary>
        ///     Sets a unsigned long in the buffer
        /// </summary>
        public unsafe void SetULong(ulong value, int position)
        {
            fixed (byte* pBuffer = Buffer)
                *(ulong*) (pBuffer + position) = value;
        }

        /// <summary>
        ///     Writes a number of empty bytes to the buffer
        /// </summary>
        /// <param name="count">Number of empty (zero) bytes to write</param>
        public void WriteZeroBytes(int count)
        {
            WriteBytes(new byte[count]);
        }

        /// <summary>
        ///     Write a string as maplestring to the buffer
        /// </summary>
        /// <param name="mString">String to write</param>
        public void WriteMapleString(string mString)
        {
            if (string.IsNullOrWhiteSpace(mString) || mString.Length == 0)
            {
                WriteZeroBytes(2);
                return;
            }
            var bytes = Encoding.UTF8.GetBytes(mString);
            WriteUShort((ushort) bytes.Length);
            WriteBytes(bytes);
        }

        /// <summary>
        ///     Creates an byte array of the current ArrayWriter
        /// </summary>
        /// <param name="direct">If true, returns a direct reference of the buffer</param>
        public byte[] ToArray(bool direct = false)
        {
            if (direct)
                return Buffer;
            var toRet = new byte[Length];
            System.Buffer.BlockCopy(Buffer, 0, toRet, 0, Length);
            return toRet;
        }

        /// <summary>
        ///     Returns a hex string representing the current ArrayWriter
        /// </summary>
        public override string ToString()
        {
            return Buffer.ToHexString();
        }
    }
}