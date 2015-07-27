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

using System;
using System.Linq;

namespace DarkMapleLib
{
    /// <summary>
    ///     Cipher class used for encrypting and decrypting maple packet data
    /// </summary>
    public class Cipher
    {
        #region Constructor and Variables

        /// <summary>
        ///     AES transformer
        /// </summary>
        private FastAes Transformer { get; }

        /// <summary>
        ///     General locker to prevent multithreading
        /// </summary>
        private volatile object _locker = new object();

        /// <summary>
        ///     Vector to use in the MapleCrypto
        /// </summary>
        private InitializationVector MapleIv { get; set; }

        /// <summary>
        ///     Gameversion of the current <see cref="Cipher" /> instance
        /// </summary>
        public ushort GameVersion { get; }

        /// <summary>
        ///     Bool stating if the current instance received its handshake
        /// </summary>
        public bool Handshaken { get; set; }

        /// <summary>
        ///     Creates a new instance of <see cref="Cipher" />
        /// </summary>
        /// <param name="currentGameVersion">The current MapleStory version</param>
        /// <param name="aesKey">AESKey for the current MapleStory version</param>
        public Cipher(ushort currentGameVersion, ulong aesKey)
        {
            Handshaken = false;
            GameVersion = currentGameVersion;
            Transformer = new FastAes(ExpandKey(aesKey));
        }

        #endregion

        #region Public Methods

        /// <summary>
        ///     Encrypts packet data
        /// </summary>
#if KMS || EMS
        public ushort? Encrypt(ref byte[] data, bool toClient)
        {
            if (!Handshaken || MapleIv == null) return null;
            ushort? ret;
#else
        public void Encrypt(ref byte[] data, bool toClient)
        {
            if (!Handshaken || MapleIv == null) return;
#endif

            var newData = new byte[data.Length + 4];
            if (toClient)
                WriteHeaderToClient(newData);
            else
                WriteHeaderToServer(newData);

#if EMS
            EncryptShanda(data);
#endif

            lock (_locker)
            {
                Transform(data);
#if KMS || EMS
                ret = MapleIv.MustSend ? MapleIv.LOWORD : null as ushort?;
#endif
            }

            Buffer.BlockCopy(data, 0, newData, 4, data.Length);
            data = newData;

#if KMS || EMS
            return ret;
#endif
        }

        /// <summary>
        ///     Decrypts a maple packet contained in <paramref name="data" />
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        public void Decrypt(ref byte[] data)
        {
            if (!Handshaken || MapleIv == null) return;
            var length = GetPacketLength(data);

            var newData = new byte[length];
            Buffer.BlockCopy(data, 4, newData, 0, length);

            lock (_locker)
            {
                Transform(newData);
            }
#if EMS
            DecryptShanda(newData);
#endif
            data = newData;
        }

        /// <summary>
        ///     Gets the length of <paramref name="data" />
        /// </summary>
        /// <param name="data">Data to check</param>
        /// <returns>Length of <paramref name="data" /></returns>
        public unsafe int GetPacketLength(byte[] data)
        {
            fixed (byte* pData = data)
            {
                return *(ushort*) pData ^ *((ushort*) pData + 1);
            }
        }

        /// <summary>
        ///     Manually sets the vector for the current instance
        /// </summary>
        public void SetIv(uint iv)
        {
            MapleIv = new InitializationVector(iv);
            Handshaken = true;
        }

        /// <summary>
        ///     Handles an handshake for the current instance
        /// </summary>
        public void Handshake(ref byte[] data)
        {
            var length = BitConverter.ToUInt16(data, 0);
            var ret = new byte[length];
            Buffer.BlockCopy(data, 2, ret, 0, ret.Length);
            data = ret;
        }

        #endregion

        #region Private Methods

        /// <summary>
        ///     Expands the key we store as long
        /// </summary>
        /// <returns>The expanded key</returns>
        private byte[] ExpandKey(ulong aesKey)
        {
            var expand = BitConverter.GetBytes(aesKey).Reverse().ToArray();
            var key = new byte[expand.Length*4];
            for (var i = 0; i < expand.Length; i++)
                key[i*4] = expand[i];
            return key;
        }

        /// <summary>
        ///     Performs Maplestory's AES algo
        /// </summary>
        private void Transform(byte[] buffer)
        {
            int remaining = buffer.Length,
                length = 0x5B0,
                start = 0;

            byte[] realIv = new byte[sizeof (int)*4],
                ivBytes = MapleIv.Bytes;

            while (remaining > 0)
            {
                for (var index = 0; index < realIv.Length; ++index)
                    realIv[index] = ivBytes[index%4];

                if (remaining < length) length = remaining;
                for (var index = start; index < (start + length); ++index)
                {
                    if (((index - start)%realIv.Length) == 0)
                        Transformer.TransformBlock(realIv);

                    buffer[index] ^= realIv[(index - start)%realIv.Length];
                }
                start += length;
                remaining -= length;
                length = 0x5B4;
            }
            MapleIv.Shuffle();
        }

        /// <summary>
        ///     Creates a packet header for outgoing data
        /// </summary>
        private unsafe void WriteHeaderToServer(byte[] data)
        {
            fixed (byte* pData = data)
            {
                *(ushort*) pData = (ushort) (GameVersion ^ MapleIv.HIWORD);
                *((ushort*) pData + 1) = (ushort) (*(ushort*) pData ^ (data.Length - 4));
            }
        }

        /// <summary>
        ///     Creates a packet header for incoming data
        /// </summary>
        private unsafe void WriteHeaderToClient(byte[] data)
        {
            fixed (byte* pData = data)
            {
                *(ushort*) pData = (ushort) (-(GameVersion + 1) ^ MapleIv.HIWORD);
                *((ushort*) pData + 1) = (ushort) (*(ushort*) pData ^ (data.Length - 4));
            }
        }

#if EMS
        /// <summary>
        ///     Decrypts <paramref name="buffer" /> using the custom MapleStory shanda
        /// </summary>
        private void DecryptShanda(byte[] buffer)
        {
            var length = buffer.Length;
            for (var passes = 0; passes < 3; passes++)
            {
                byte xorKey = 0;
                byte save;
                var len = (byte) (length & 0xFF);
                byte temp;
                for (var i = length - 1; i >= 0; --i)
                {
                    temp = (byte) (ROL(buffer[i], 3) ^ 0x13);
                    save = temp;
                    temp = ROR((byte) ((xorKey ^ temp) - len), 4);
                    xorKey = save;
                    buffer[i] = temp;
                    --len;
                }

                xorKey = 0;
                len = (byte) (length & 0xFF);
                for (var i = 0; i < length; ++i)
                {
                    temp = ROL((byte) (~(buffer[i] - 0x48)), len & 0xFF);
                    save = temp;
                    temp = ROR((byte) ((xorKey ^ temp) - len), 3);
                    xorKey = save;
                    buffer[i] = temp;
                    --len;
                }
            }
        }

        /// <summary>
        ///     Encrypts <paramref name="buffer" /> using the custom MapleStory shanda
        /// </summary>
        private void EncryptShanda(byte[] buffer)
        {
            var length = buffer.Length;
            byte xorKey, len, temp;
            int i;
            for (var passes = 0; passes < 3; passes++)
            {
                xorKey = 0;
                len = (byte) (length & 0xFF);
                for (i = 0; i < length; i++)
                {
                    temp = (byte) ((ROL(buffer[i], 3) + len) ^ xorKey);
                    xorKey = temp;
                    temp = (byte) (((~ROR(temp, len & 0xFF)) & 0xFF) + 0x48);
                    buffer[i] = temp;
                    len--;
                }
                xorKey = 0;
                len = (byte) (length & 0xFF);
                for (i = length - 1; i >= 0; i--)
                {
                    temp = (byte) (xorKey ^ (len + ROL(buffer[i], 4)));
                    xorKey = temp;
                    temp = ROR((byte) (temp ^ 0x13), 3);
                    buffer[i] = temp;
                    len--;
                }
            }
        }

        /// <summary>
        ///     Bitwise shift left
        /// </summary>
        private byte ROL(byte b, int count)
        {
            var tmp = b << (count & 7);
            return unchecked((byte) (tmp | (tmp >> 8)));
        }

        /// <summary>
        ///     Bitwise shift right
        /// </summary>
        private byte ROR(byte b, int count)
        {
            var tmp = b << (8 - (count & 7));
            return unchecked((byte) (tmp | (tmp >> 8)));
        }
#endif

        #endregion
    }
}

// ReSharper disable once InconsistentNaming