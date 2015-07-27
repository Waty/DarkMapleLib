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
    ///     Extensions to make life easier
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        ///     Converts a byte array to a hexadecimal string
        /// </summary>
        public static string ToHexString(this byte[] bArray, bool appendSpace = true)
        {
            var sb = new StringBuilder();
            foreach (var b in bArray)
                if (appendSpace)
                {
                    sb.Append(b.ToString("X2"));
                    sb.Append(' ');
                }
                else
                    sb.Append(b.ToString("X2"));
            return sb.ToString();
        }
    }
}