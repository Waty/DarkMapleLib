﻿/*!
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
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DarkMapleLib.Helpers
{
    /// <summary>
    /// Helper class for Cipher related functionality
    /// </summary>
    public class CipherHelper
    {
        #region Constructor and Variables
        /// <summary>
        /// Packet crypto, Incomming
        /// </summary>
        private Cipher RecvCipher { get; set; }

        /// <summary>
        /// Packet crypto, Outgoing
        /// </summary>
        private Cipher SendCipher { get; set; }

        /// <summary>
        /// Waiting state
        /// </summary>
        private bool IsWaiting { get; set; }

        /// <summary>
        /// Data buffer
        /// </summary>
        private byte[] DataBuffer { get; set; }

        /// <summary>
        /// Current data in buffer
        /// </summary>
        private int AvailableData { get; set; }

        /// <summary>
        /// Amount of data to wait on
        /// </summary>
        private int WaitForData { get; set; }

        /// <summary>
        /// General locker for adding data
        /// </summary>
        private Object AddLocker = new Object();

        /// <summary>
        /// Creates a new instance of <see cref="CipherHelper"/>
        /// </summary>
        /// <param name="currentGameVersion">The current MapleStory version</param>
        /// <param name="AESKey">AESKey for the current MapleStory version</param>
        /// <param name="initialBufferSize">Sets the initial size of the buffer</param>
        public CipherHelper(UInt16 currentGameVersion, UInt64 AESKey, UInt16 initialBufferSize = 0x100)
        {
            RecvCipher = new Cipher(currentGameVersion, AESKey);
            SendCipher = new Cipher(currentGameVersion, AESKey);

            DataBuffer = new byte[initialBufferSize];
            AvailableData = 0;
            WaitForData = 0;
            IsWaiting = true;
        }
        #endregion

        #region Events
        /// <summary>
        /// Callback for when a packet is finished
        /// </summary>
        public delegate void CallPacketFinished(byte[] packet);

        /// <summary>
        /// Event called when a packet has been handled by the crypto
        /// </summary>
        public event CallPacketFinished PacketFinished;

        /// <summary>
        /// Callback for when a handshake is finished
        /// </summary>
        public delegate void CallHandshakeFinished(UInt32 SIV, UInt32 RIV);

        /// <summary>
        /// Event called when a handshake has been handled by the crypto
        /// </summary>
        public event CallHandshakeFinished HandshakeFinished;
        #endregion

        #region Public Methods
        /// <summary>
        /// Adds data to the buffer to await decryption
        /// </summary>
        public void AddData(byte[] data)
        {
            int length = data.Length;
            lock (AddLocker)
            {
                EnsureCapacity(length + AvailableData);
                Buffer.BlockCopy(data, 0, DataBuffer, AvailableData, length);
                AvailableData += length;
            }
            if (WaitForData != 0)
            {
                if (WaitForData <= AvailableData)
                {
                    int w = WaitForData - 2;
                    if (RecvCipher.Handshaken)
                        w -= 2;

                    WaitForData = 0;
                    WaitMore(w);
                }
            }
            if (IsWaiting)
                Wait();
        }

        /// <summary>
        /// Sets the Recv and Send Vectors for the ciphers
        /// </summary>
        public void SetVectors(uint SIV, uint RIV)
        {
            SendCipher.SetIV(SIV);
            RecvCipher.SetIV(RIV);
        }

        /// <summary>
        /// Encrypts packet data
        /// </summary>
#if KMS || EMS
        public UInt16? Encrypt(ref byte[] data, bool toClient = false)
        {
            return SendCipher.Encrypt(ref data, toClient);
        }
#else
        public void Encrypt(ref byte[] data, bool toClient = false)
        {
            SendCipher.Encrypt(ref data, toClient);
        }
#endif
        #endregion

        #region Private Methods

        /// <summary>
        /// Prevents the buffer being to small
        /// </summary>
        private void EnsureCapacity(int length)
        {
            if (DataBuffer.Length > length) return; //Return as quikly as posible
            byte[] newBuffer = new byte[DataBuffer.Length + 0x50];
            System.Buffer.BlockCopy(DataBuffer, 0, newBuffer, 0, DataBuffer.Length);
            DataBuffer = newBuffer;
            EnsureCapacity(length);
        }

        /// <summary>
        /// Checks if there is enough data to read, Or waits if there isn't.
        /// </summary>
        private void Wait()
        {
            if (!IsWaiting)
                IsWaiting = true;

            if (AvailableData >= 4)
            {
                IsWaiting = false;
                GetHeader();
            }
        }

        /// <summary>
        /// Second step of the wait sequence
        /// </summary>
        private void WaitMore(int length)
        {
            int add = RecvCipher.Handshaken ? 4 : 2;

            if (AvailableData < (length + add))
            {
                WaitForData = length + add;
                return;
            }

            byte[] data;

            data = new byte[length + add];
            Buffer.BlockCopy(DataBuffer, 0, data, 0, data.Length);
            Buffer.BlockCopy(DataBuffer, length + add, DataBuffer, 0, DataBuffer.Length - (length + add));
            AvailableData -= (length + add);

            Decrypt(data.ToArray());
        }

        /// <summary>
        /// Decrypts the packet data
        /// </summary>
        private void Decrypt(byte[] data)
        {
            if (!RecvCipher.Handshaken)
            {
                RecvCipher.Handshake(ref data);
                ArrayReader pr = new ArrayReader(data);
                Debug.WriteLine("Server version {0}.{1}", pr.ReadShort(), pr.ReadMapleString());
                uint siv = pr.ReadUInt();
                uint riv = pr.ReadUInt();
                SendCipher.SetIV(siv);
                RecvCipher.SetIV(riv);

                if (HandshakeFinished != null)
                    HandshakeFinished(siv, riv);
            }
            else
            {
                RecvCipher.Decrypt(ref data);
                if (data.Length == 0) return;

                if (PacketFinished != null)
                    PacketFinished(data);
            }
            Wait();
        }

        /// <summary>
        /// Gets the packet header from the current packet.
        /// </summary>
        private void GetHeader()
        {
            if (!RecvCipher.Handshaken)
                WaitMore(BitConverter.ToUInt16(DataBuffer, 0));
            else
            {
                int packetLength = RecvCipher.GetPacketLength(DataBuffer);
                WaitMore(packetLength);
            }
        }
        #endregion
    }
}
