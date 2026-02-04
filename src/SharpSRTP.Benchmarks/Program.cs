using BenchmarkDotNet.Running;

namespace SharpSRTP.Benchmarks
{
    static class Program
    {
        public static void Main(string[] args)
        {
            BenchmarkRunner.Run<SrtpProtectUnprotectBenchmark>();
        }
    }
}
