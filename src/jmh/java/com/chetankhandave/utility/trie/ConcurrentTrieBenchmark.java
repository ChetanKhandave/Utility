package com.chetankhandave.utility.trie;

import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Group;
import org.openjdk.jmh.annotations.GroupThreads;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.ThreadParams;

/** Measures throughput and sampled latency for a shared concurrent trie. */
@BenchmarkMode({Mode.Throughput, Mode.SampleTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(2)
public class ConcurrentTrieBenchmark {

    /** Prepares key strings outside the measured operations. */
    @State(Scope.Benchmark)
    public static class Dataset {
        @Param({"100000", "1000000"})
        public int keyCount;

        @Param({"shared", "spread"})
        public String shape;

        private String[] keys;
        private String[] misses;

        @Setup
        public void prepare() {
            Logger.getLogger(ConcurrentLinkedSiblingPrefixTree.class.getName()).setLevel(Level.OFF);
            keys = new String[keyCount];
            misses = new String[keyCount];
            for (int index = 0; index < keyCount; index++) {
                String branch = "spread".equals(shape) ? bucket(index) : "";
                String digits = Integer.toString(1_000_000 + index).substring(1);
                String prefix = branch + "employee-" + digits;
                keys[index] = prefix + "-a";
                misses[index] = prefix + "-x";
            }
        }

        private ConcurrentLinkedSiblingPrefixTree build() {
            ConcurrentLinkedSiblingPrefixTree tree = new ConcurrentLinkedSiblingPrefixTree();
            for (String key : keys) {
                tree.add(key);
            }
            return tree;
        }

        private static String bucket(int index) {
            return String.valueOf((char) ('a' + index % 26)) + '-';
        }
    }

    /** Shares one trie across the workers in each benchmark group. */
    @State(Scope.Group)
    public static class SharedTrie {
        private ConcurrentLinkedSiblingPrefixTree tree;

        @Setup
        public void preload(Dataset dataset) {
            tree = dataset.build();
        }
    }

    /** Gives each worker an independent, repeatable lookup sequence. */
    @State(Scope.Thread)
    public static class Lookup {
        private int random;

        @Setup
        public void seed(ThreadParams thread) {
            random = 0x9e3779b9 + thread.getThreadIndex();
        }

        private boolean find(SharedTrie shared, Dataset dataset) {
            random ^= random << 13;
            random ^= random >>> 17;
            random ^= random << 5;
            int index = (random & Integer.MAX_VALUE) % dataset.keys.length;
            // Use a different random bit to mix hits with near-end misses.
            String key = random < 0 ? dataset.misses[index] : dataset.keys[index];
            return shared.tree.contains(key);
        }
    }

    /** Owns a preloaded key and its alternate so each replacement succeeds. */
    @State(Scope.Thread)
    public static class Writer {
        private String from;
        private String to;

        @Setup
        public void prepare(Dataset dataset, ThreadParams thread) {
            from = dataset.keys[thread.getSubgroupThreadIndex()];
            to = from.substring(0, from.length() - 1) + "b";
        }

        private boolean replace(SharedTrie shared) {
            if (!shared.tree.replace(from, to)) {
                throw new IllegalStateException("Writer lost its exclusively assigned key");
            }
            String previous = from;
            from = to;
            to = previous;
            return true;
        }
    }

    /** Measures elapsed time per complete load into an empty trie. */
    @Benchmark
    @BenchmarkMode(Mode.SingleShotTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Threads(1)
    public ConcurrentLinkedSiblingPrefixTree bulkLoad(Dataset dataset) {
        return dataset.build();
    }

    @Benchmark
    @Group("readOnly")
    @GroupThreads(8)
    public boolean readOnly(SharedTrie shared, Dataset dataset, Lookup lookup) {
        return lookup.find(shared, dataset);
    }

    @Benchmark
    @Group("readHeavy")
    @GroupThreads(7)
    public boolean readHeavyLookup(SharedTrie shared, Dataset dataset, Lookup lookup) {
        return lookup.find(shared, dataset);
    }

    @Benchmark
    @Group("readHeavy")
    @GroupThreads(1)
    public boolean readHeavyReplace(SharedTrie shared, Writer writer) {
        return writer.replace(shared);
    }

    @Benchmark
    @Group("writeHeavy")
    @GroupThreads(2)
    public boolean writeHeavyLookup(SharedTrie shared, Dataset dataset, Lookup lookup) {
        return lookup.find(shared, dataset);
    }

    @Benchmark
    @Group("writeHeavy")
    @GroupThreads(6)
    public boolean writeHeavyReplace(SharedTrie shared, Writer writer) {
        return writer.replace(shared);
    }
}
