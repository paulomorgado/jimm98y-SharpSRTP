using BenchmarkDotNet.Attributes;
using SharpSRTP.SRTP;
using System;


#if !NET5_0_OR_GREATER
using Convert2 = SharpSRTP.Tests.Convert;
#else
using Convert2 = System.Convert;
#endif

namespace SharpSRTP.Benchmarks
{
    public class SrtpSessionContextBenchmarks
    {
        private const string MasterKeySaltBase64 = "n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi";
        private const string RtpHex = "80e1000103cb6bc84218a6a3001006c801123318f6882d06086141a9c44dfbfb7e9f1cf997eb257b77c732bcf779ae750b6493aff001815dcfc814a4fb96089153b0becc4e091f2632584ee88fc01701a0dc5111f3d7b201b0a5496972275d00e503d921370ecbdebc5ac4e54572e59ca65c29ce246b438659df04633d5d0452da1b9ce729670a616b4f5050df2c7de897ca16f5762d6df93da0134d6c3d2fedb178be2fbbfa3c702673c231d5af4f1c9b2fa791a19ef3a23aee2325dc633f19ebde33f0eeec8351cfa62bbbf9339d6b7e322ba3bb5e1d31a3956475cf450984d4a274d2583d1b80e0";

        private byte[] _masterKeySaltBytes;
        private byte[] _rtpBytes;
        private byte[] _srtpBytes;
        private SrtpKeys _keys;
        private SrtpSessionContext _context;

        [GlobalSetup]
        public void GlobalSetup()
        {
            _masterKeySaltBytes = System.Convert.FromBase64String(MasterKeySaltBase64);
            _rtpBytes = Convert2.FromHexString(RtpHex);
            _keys = SrtpProtocol.CreateMasterKeys(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80, null, _masterKeySaltBytes);
            _context = SrtpProtocol.CreateSrtpSessionContext(_keys);
            _srtpBytes = new byte[_context.CalculateRequiredSrtpPayloadLength(_rtpBytes.Length)];
            Buffer.BlockCopy(_rtpBytes, 0, _srtpBytes, 0, _rtpBytes.Length);
        }

        [Benchmark]
        public SrtpSessionContext CreateSrtpSessionContext()
        {
            return SrtpProtocol.CreateSrtpSessionContext(_keys);
        }
    }
}
