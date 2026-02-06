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
using SharpSRTP.SRTP;

namespace SharpSRTP.DTLSSRTP
{
    public class DtlsSrtpKeys
    {
        public SrtpProtectionProfileConfiguration ProtectionProfile { get; }
        public ArraySegment<byte> Mki { get; }

        public ArraySegment<byte> ClientWriteMasterKey { get; }
        public ArraySegment<byte> ClientWriteMasterSalt { get; }
        public ArraySegment<byte> ServerWriteMasterKey { get; }
        public ArraySegment<byte> ServerWriteMasterSalt { get; }

        public DtlsSrtpKeys(
            SrtpProtectionProfileConfiguration protectionProfile,
            ArraySegment<byte> clientWriteMasterKey,
            ArraySegment<byte> clientWriteMasterSalt,
            ArraySegment<byte> serverWriteMasterKey,
            ArraySegment<byte> serverWriteMasterSalt,
            ArraySegment<byte> mki = default)
        {
            this.ProtectionProfile = protectionProfile ?? throw new ArgumentNullException(nameof(protectionProfile));
            this.Mki = mki;

            int cipherKeyLen = protectionProfile.CipherKeyLength >> 3;
            int cipherSaltLen = protectionProfile.CipherSaltLength >> 3;

            if (clientWriteMasterKey.Count != cipherKeyLen
                || clientWriteMasterSalt.Count != cipherSaltLen
                || serverWriteMasterKey.Count != cipherKeyLen
                || serverWriteMasterSalt.Count != cipherSaltLen)

            this.ClientWriteMasterKey = clientWriteMasterKey;
            this.ClientWriteMasterSalt = clientWriteMasterSalt;
            this.ServerWriteMasterKey = serverWriteMasterKey;
            this.ServerWriteMasterSalt = serverWriteMasterSalt;
        }
    }
}
