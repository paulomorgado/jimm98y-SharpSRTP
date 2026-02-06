// SharpSRTP
// Copyright (C) 2025 Lukas Volf
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

using System;
using System.Linq;
using System.Reflection;

namespace SharpSRTP.SRTP
{
    public class SrtpKeys
    {
        public SrtpProtectionProfileConfiguration ProtectionProfile { get; }
        public ArraySegment<byte> Mki { get; }

        public ArraySegment<byte> MasterKey { get; }
        public ArraySegment<byte> MasterSalt { get; }
        public ArraySegment<byte> MasterKeySalt { get; }

        public SrtpKeys(SrtpProtectionProfileConfiguration protectionProfile, byte[] masterKeySalt, byte[] mki = default)
        {
#if NET8_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(protectionProfile);
            this.ProtectionProfile = protectionProfile;

            ArgumentNullException.ThrowIfNull(masterKeySalt);
            this.MasterKeySalt = masterKeySalt;
#else
            this.ProtectionProfile = protectionProfile ?? throw new ArgumentNullException(nameof(protectionProfile));

            this.MasterKeySalt = new ArraySegment<byte>(masterKeySalt ?? throw new ArgumentNullException(nameof(masterKeySalt)));
#endif

            if (masterKeySalt.Length != (protectionProfile.CipherKeyLength + protectionProfile.CipherSaltLength) >> 3)
            {
                throw new ArgumentException($"'{masterKeySalt}' length does not match profile requirements", nameof(masterKeySalt));
            }

            MasterKey = MasterKeySalt.Slice(0, ProtectionProfile.CipherKeyLength >> 3);
            MasterSalt = MasterKeySalt.Slice(ProtectionProfile.CipherKeyLength >> 3);

            this.Mki = new ArraySegment<byte>(mki ?? Array.Empty<byte>());
        }
    }
}
