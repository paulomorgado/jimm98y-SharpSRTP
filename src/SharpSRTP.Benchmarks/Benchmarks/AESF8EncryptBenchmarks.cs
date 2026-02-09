using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using SharpSRTP.SRTP.Encryption;
using SharpSRTP.SRTP.Readers;
using System;

namespace SharpSRTP.Benchmarks
{
    public class AESF8EncryptBenchmarks
    {
        private static readonly byte[] k_e;
        private static readonly byte[] k_s;
        private static readonly byte[] rtpBytesSource;
        private static readonly uint roc = 0xd462564a;
        private byte[] rtpBytes;
        private AesEngine aes;

        static AESF8EncryptBenchmarks()
        {
            k_e = Convert.FromHexString("234829008467be186c3de14aae72d62c");
            k_s = Convert.FromHexString("32f2870d");
            rtpBytesSource = Convert.FromHexString("806e5cba50681de55c62159970736575646f72616e646f6d6e65737320697320746865206e6578742062657374207468696e67");
        }

        [GlobalSetup]
        public void GlobalSetup()
        {
        }

        [IterationSetup]
        public void IterationSetup()
        {
            aes = new AesEngine();
            rtpBytes = new byte[rtpBytesSource.Length];
            Buffer.BlockCopy(rtpBytesSource, 0, rtpBytes, 0, rtpBytesSource.Length);

            uint sequenceNumber = RtpReader.ReadSequenceNumber(rtpBytesSource);
            uint ssrc = RtpReader.ReadSsrc(rtpBytesSource);
            int offset = RtpReader.ReadHeaderLen(rtpBytesSource);
            ulong index = ((ulong)roc << 16) | sequenceNumber;

            aes1 = new AesEngine();
            aes2 = new AesEngine();
            iv = F8.GenerateRtpMessageKeyIV(aes, k_e, k_s, rtpBytesSource, roc);
            aes2.Init(true, new KeyParameter(k_e));
        }

        [Benchmark]
        public void AESF8_Encrypt()
        {
            int offset = RtpReader.ReadHeaderLen(rtpBytesSource);

            byte[] iv = F8.GenerateRtpMessageKeyIV(aes, k_e, k_s, rtpBytesSource, roc);

            aes.Init(true, new KeyParameter(k_e));
            F8.Encrypt(aes, rtpBytesSource, offset, rtpBytesSource.Length, iv);
        }

        private byte[] iv;
        private AesEngine aes1;
        private AesEngine aes2;
        [Benchmark]
        public void AESF8_Encrypt_1()
        {
            byte[] iv = F8.GenerateRtpMessageKeyIV(aes, k_e, k_s, rtpBytesSource, roc);
        }

        [Benchmark]
        public void AESF8_Encrypt_2()
        {
            aes1.Init(true, new KeyParameter(k_e));
        }

        [Benchmark]
        public void AESF8_Encrypt_3()
        {
            int offset = RtpReader.ReadHeaderLen(rtpBytesSource);
            F8.Encrypt(aes2, rtpBytesSource, offset, rtpBytesSource.Length, iv);
        }
    }
}
