using BenchmarkDotNet.Attributes;
using SharpSRTP.DTLSSRTP;
using SharpSRTP.SRTP;
using System;
using System.Collections.Generic;



#if !NET5_0_OR_GREATER
using Convert2 = SharpSRTP.Tests.Convert;
#else
using Convert2 = System.Convert;
#endif

namespace SharpSRTP.Benchmarks
{
    public class RtpProtectUnprotectBenchmarks
    {
        [ParamsSource(nameof(SettingsSource))]
        public RtpProtectUnprotectSettings Settings { get; set; }


        [Benchmark]
        public void Srtp_Protect_Unprotect()
        {
            Settings.Context.ProtectRtp(Settings.SrtpBytes, Settings.RtpBytes.Length, out var len);

            Settings.Context.UnprotectRtp(Settings.SrtpBytes, len, out var _);
        }

        public static IEnumerable<RtpProtectUnprotectSettings> SettingsSource =>
            new[]
            {
                new RtpProtectUnprotectSettings(
                    cryptoSuite: SrtpCryptoSuites.AES_CM_128_HMAC_SHA1_80,
                    masterKeySaltBytes: System.Convert.FromBase64String("n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi"),
                    rtpBytes: Convert2.FromHexString("80e1000103cb6bc84218a6a3001006c801123318f6882d06086141a9c44dfbfb7e9f1cf997eb257b77c732bcf779ae750b6493aff001815dcfc814a4fb96089153b0becc4e091f2632584ee88fc01701a0dc5111f3d7b201b0a5496972275d00e503d921370ecbdebc5ac4e54572e59ca65c29ce246b438659df04633d5d0452da1b9ce729670a616b4f5050df2c7de897ca16f5762d6df93da0134d6c3d2fedb178be2fbbfa3c702673c231d5af4f1c9b2fa791a19ef3a23aee2325dc633f19ebde33f0eeec8351cfa62bbbf9339d6b7e322ba3bb5e1d31a3956475cf450984d4a274d2583d1b80e0")),
                //new RtpProtectUnprotectSettings(
                //    cryptoSuite: ExtendedSrtpProtectionProfile.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM,
                //    masterKeySaltBytes: System.Convert.FromBase64String("n7z9GgmnJ4Bc2hC0prEf8KFCKv8EyG+4WrUOg7oi"),
                //    rtpBytes: Convert2.FromHexString("80e1000103cb6bc84218a6a3001006c801123318f6882d06086141a9c44dfbfb7e9f1cf997eb257b77c732bcf779ae750b6493aff001815dcfc814a4fb96089153b0becc4e091f2632584ee88fc01701a0dc5111f3d7b201b0a5496972275d00e503d921370ecbdebc5ac4e54572e59ca65c29ce246b438659df04633d5d0452da1b9ce729670a616b4f5050df2c7de897ca16f5762d6df93da0134d6c3d2fedb178be2fbbfa3c702673c231d5af4f1c9b2fa791a19ef3a23aee2325dc633f19ebde33f0eeec8351cfa62bbbf9339d6b7e322ba3bb5e1d31a3956475cf450984d4a274d2583d1b80e0")),
            };

        public sealed class RtpProtectUnprotectSettings
        {
            public RtpProtectUnprotectSettings(
                string cryptoSuite,
                byte[] masterKeySaltBytes,
                byte[] rtpBytes)
            {
                CryptoSuite = cryptoSuite;
                RtpBytes = rtpBytes;
                var keys = SrtpProtocol.CreateMasterKeys(CryptoSuite, null, masterKeySaltBytes);
                Context = SrtpProtocol.CreateSrtpSessionContext(keys);
                SrtpBytes = new byte[Context.CalculateRequiredSrtpPayloadLength(RtpBytes.Length)];
                Buffer.BlockCopy(RtpBytes, 0, SrtpBytes, 0, RtpBytes.Length);
            }

            public string CryptoSuite { get; }

            public byte[] RtpBytes { get; }

            public byte[] SrtpBytes { get; }

            public SrtpSessionContext Context { get; }

            public override string ToString() => CryptoSuite;
        }
    }
}
