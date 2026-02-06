using BenchmarkDotNet.Attributes;
using SharpSRTP.SRTP;


#if !NET5_0_OR_GREATER
using Convert2 = SharpSRTP.Tests.Convert;
#else
using Convert2 = System.Convert;
#endif

namespace SharpSRTP.Benchmarks
{
    public class CreateMasterKeysBenchmarks
    {
        private const string MasterKeySaltBase64 = "n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi";

        private byte[] _masterKeySaltBytes;

        [GlobalSetup]
        public void GlobalSetup()
        {
            _masterKeySaltBytes = System.Convert.FromBase64String(MasterKeySaltBase64);
        }

        [Benchmark]
        public SrtpKeys CreateMasterKeys()
        {
            return SrtpProtocol.CreateMasterKeys(SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80, null, _masterKeySaltBytes);
        }
    }
}
