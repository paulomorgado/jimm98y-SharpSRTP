using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Order;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;


#if !NET5_0_OR_GREATER
using Convert2 = SharpSRTP.Tests.Convert;
#else
#endif

namespace SharpSRTP.Benchmarks;

internal sealed class Config : ManualConfig
{
    public Config()
    {
        Runtime[] targetRuntimes = [CoreRuntime.Core10_0, /*CoreRuntime.Core80, */ClrRuntime.Net481];

        AddJobs(true, "0.3.1", targetRuntimes);
        AddJobs(false, "", targetRuntimes);

        AddExporter(BenchmarkDotNet.Exporters.MarkdownExporter.GitHub);

        AddColumnProvider(BenchmarkDotNet.Columns.DefaultColumnProviders.Instance);
        HideColumns(Column.Arguments, Column.Error, Column.Median, Column.StdDev, Column.RatioSD);

        WithSummaryStyle(SummaryStyle.Default.WithMaxParameterColumnWidth(int.MaxValue));

        AddDiagnoser(BenchmarkDotNet.Diagnosers.MemoryDiagnoser.Default);

        AddLogger(BenchmarkDotNet.Loggers.ConsoleLogger.Default);

        void AddJobs(bool baseline, string version, params Runtime[] targetRuntimes)
        {
            foreach (var targetRuntime in targetRuntimes)
            {
                AddJob(Job.MediumRun
                    .WithRuntime(targetRuntime)
                    .WithMsBuildArguments($"/p:LibVersion={version}")
                    .WithId(string.IsNullOrEmpty(version) ? "this" : version)
                    .WithBaseline(baseline)
                )
                    .WithOrderer(new MethodJobRuntimeOrderer())
                ;

                baseline = false;
            }
        }
    }

    private sealed class MethodJobRuntimeOrderer : IOrderer
    {
        public IEnumerable<BenchmarkCase> GetExecutionOrder(
            ImmutableArray<BenchmarkCase> benchmarksCase,
            IEnumerable<BenchmarkLogicalGroupRule>? order = null)
            => benchmarksCase;

        public IEnumerable<BenchmarkCase> GetSummaryOrder(
            ImmutableArray<BenchmarkCase> benchmarksCases,
            Summary summary)
            => benchmarksCases
                .OrderBy(b => b.Descriptor.WorkloadMethod.Name)
                .ThenBy(b => b.Job.Environment.Runtime?.Name)
                .ThenBy(b => b.Job.DisplayInfo);

        public string? GetHighlightGroupKey(BenchmarkCase benchmarkCase) => null;

        public string? GetLogicalGroupKey(
            ImmutableArray<BenchmarkCase> allBenchmarksCases,
            BenchmarkCase benchmarkCase) => null;

        public IEnumerable<IGrouping<string, BenchmarkCase>> GetLogicalGroupOrder(
            IEnumerable<IGrouping<string, BenchmarkCase>> logicalGroups,
            IEnumerable<BenchmarkLogicalGroupRule>? order = null)
            => logicalGroups;

        public bool SeparateLogicalGroups => false;
    }
}
