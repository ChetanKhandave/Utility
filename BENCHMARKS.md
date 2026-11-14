# Concurrent trie benchmarks

Build the JMH runner with a JDK and Maven from the repository root.

```sh
mvn -Pbenchmarks clean package
java -jar target/utility-1.0-SNAPSHOT-benchmarks.jar ConcurrentTrieBenchmark
```

Verify benchmark discovery with `java -jar target/utility-1.0-SNAPSHOT-benchmarks.jar -l` after a clean build. JMH generates `META-INF/BenchmarkList` during compilation. The benchmarks profile checks for that file before packaging.

Run a short smoke test with smaller inputs.

```sh
java -jar target/utility-1.0-SNAPSHOT-benchmarks.jar ConcurrentTrieBenchmark -p keyCount=1000 -p shape=shared -f 1 -wi 0 -i 1 -r 200ms
```

| Benchmark | Workload |
|---|---|
| `bulkLoad` | One worker loads an empty trie. Results are milliseconds per complete load. |
| `readOnly` | Eight lookup workers share a preloaded trie. |
| `readHeavy` | Seven lookup workers and one replacement worker share a preloaded trie. |
| `writeHeavy` | Two lookup workers and six replacement workers share a preloaded trie. |

The default datasets contain 100,000 and 1,000,000 distinct keys. The
`shared` shape uses a common leading prefix. The `spread` shape distributes
keys across 26 leading branches. Lookups mix hits and near-end misses.
Each writer alternates between its own pair of keys, keeping the trie size
stable. Thread counts describe the worker mix. The measured operation mix
depends on each worker's throughput.

JMH reports throughput in ops/µs and sample latency in µs/op. Inspect the
lookup and replacement rows separately in the mixed groups, including their
p95 and p99 percentiles. Trace logging is disabled in the benchmark forks.
Key generation and preloading for the mixed groups happen outside measurement.

To record results and allocation statistics, append
`-rf json -rff trie-results.json -prof gc` to the runner command.
