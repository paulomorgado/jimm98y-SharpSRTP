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

using Org.BouncyCastle.Crypto;
using System;

namespace SharpSRTP.SRTP.Encryption
{
    public static class CTR
    {
        public const int BLOCK_SIZE = 16;

        public static byte[] GenerateSessionKeyIV(byte[] masterSalt, ulong index, ulong kdr, byte label)
        {
            byte[] iv = GC.AllocateUninitializedArray<byte>(BLOCK_SIZE);

            // RFC 3711 - 4.3.1
            // Key derivation SHALL be defined as follows in terms of<label>, an
            // 8 - bit constant(see below), master_salt and key_derivation_rate, as
            // determined in the cryptographic context, and index, the packet index
            // (i.e., the 48 - bit ROC || SEQ for SRTP):

            // *Let r = index DIV key_derivation_rate(with DIV as defined above).
            ulong r = DIV(index, kdr);

            // *Let key_id = < label > || r.
            ulong keyId = ((ulong)label << 48) | r;

            // *Let x = key_id XOR master_salt, where key_id and master_salt are
            //  aligned so that their least significant bits agree(right-
            //  alignment).
            Buffer.BlockCopy(masterSalt, 0, iv, 0, masterSalt.Length);

            // XOR with keyId at offset 7 (7 bytes)
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(iv.AsSpan(7, 8), 
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(iv.AsSpan(7, 8)) ^ keyId);

            iv[14] = 0;
            iv[15] = 0;

            return iv;
        }

        private static ulong DIV(ulong x, ulong y)
        {
            if (y == 0)
            {
                return 0;
            }
            else
            {
                return x / y;
            }
        }

        public static byte[] GenerateMessageKeyIV(byte[] salt, uint ssrc, ulong index)
        {
            // RFC 3711 - 4.1.1
            // IV = (k_s * 2 ^ 16) XOR(SSRC * 2 ^ 64) XOR(i * 2 ^ 16)
            byte[] iv = GC.AllocateUninitializedArray<byte>(16);

            Buffer.BlockCopy(salt, 0, iv, 0, 14);

            // XOR SSRC at offset 4
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(iv.AsSpan(4, 4),
                System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(iv.AsSpan(4, 4)) ^ ssrc);

            // XOR index at offset 8
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(iv.AsSpan(8, 8),
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(iv.AsSpan(8, 8)) ^ index);

            iv[14] = 0;
            iv[15] = 0;

            return iv;
        }

        public static void Encrypt(IBlockCipher engine, byte[] payload, int offset, int length, byte[] iv)
        {
            int payloadSize = length - offset;
            byte[] cipher = GC.AllocateUninitializedArray<byte>(payloadSize);

            int blockNo = 0;
            for (int i = 0; i < payloadSize / BLOCK_SIZE; i++)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(iv.AsSpan(14, 2), (ushort)i);
                engine.ProcessBlock(iv, 0, cipher, BLOCK_SIZE * blockNo);
                blockNo++;
            }

            if (payloadSize % BLOCK_SIZE != 0)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(iv.AsSpan(14, 2), (ushort)blockNo);
                byte[] lastBlock = GC.AllocateUninitializedArray<byte>(BLOCK_SIZE);
                engine.ProcessBlock(iv, 0, lastBlock, 0);
                Buffer.BlockCopy(lastBlock, 0, cipher, BLOCK_SIZE * blockNo, payloadSize % BLOCK_SIZE);
            }

            for (int i = 0; i < payloadSize; i++)
            {
                payload[offset + i] ^= cipher[i];
            }
        }
    }
}
