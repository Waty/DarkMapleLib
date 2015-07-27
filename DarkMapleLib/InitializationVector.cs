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

namespace DarkMapleLib
{
    /// <summary>
    ///     Initialization vector used by the Cipher class
    /// </summary>
    internal class InitializationVector
    {
        /// <summary>
        ///     IV Container
        /// </summary>
        private uint _value;

        /// <summary>
        ///     Creates a IV instance using <paramref name="vector" />
        /// </summary>
        /// <param name="vector">Initialization vector</param>
        internal InitializationVector(uint vector)
        {
            _value = vector;
        }

        /// <summary>
        ///     Gets the bytes of the current container
        /// </summary>
        internal byte[] Bytes => BitConverter.GetBytes(_value);

        /// <summary>
        ///     Gets the HIWORD from the current container
        /// </summary>
        // ReSharper disable once InconsistentNaming
        internal ushort HIWORD => unchecked((ushort) (_value >> 16));

        /// <summary>
        ///     Gets the LOWORD from the current container
        /// </summary>
        // ReSharper disable once InconsistentNaming
        internal ushort LOWORD => (ushort) _value;

#if KMS || EMS
        /// <summary>
        ///     IV Security check
        /// </summary>
        internal bool MustSend => LOWORD%0x1F == 0;
#endif

        /// <summary>
        ///     Shuffles the current IV to the next vector using the shuffle table
        /// </summary>
        internal unsafe void Shuffle()
        {
            var key = Constants.DefaultKey;
            var pKey = &key;
            fixed (uint* pIv = &_value)
            {
                fixed (byte* pShuffle = Constants.Shuffle)
                {
                    for (var i = 0; i < 4; i++)
                    {
                        *((byte*) pKey + 0) += (byte) (*(pShuffle + *((byte*) pKey + 1)) - *((byte*) pIv + i));
                        *((byte*) pKey + 1) -= (byte) (*((byte*) pKey + 2) ^ *(pShuffle + *((byte*) pIv + i)));
                        *((byte*) pKey + 2) ^= (byte) (*((byte*) pIv + i) + *(pShuffle + *((byte*) pKey + 3)));
                        *((byte*) pKey + 3) =
                            (byte) (*((byte*) pKey + 3) - *(byte*) pKey + *(pShuffle + *((byte*) pIv + i)));

                        *pKey = (*pKey << 3) | (*pKey >> (32 - 3));
                    }
                }
            }

            _value = key;
        }
    }
}