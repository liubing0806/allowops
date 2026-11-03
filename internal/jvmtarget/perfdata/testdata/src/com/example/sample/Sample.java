package com.example.sample;

import java.util.ArrayList;
import java.util.List;

/** Allocates, loads classes and starts threads so that the PerfData counters are non-trivial. */
public class Sample {
    public static void main(String[] args) throws Exception {
        List<byte[]> keep = new ArrayList<>();
        for (int i = 0; i < 400; i++) {
            keep.add(new byte[64 * 1024]);
            if (keep.size() > 40) {
                keep.remove(0);
            }
        }
        Class.forName("java.util.concurrent.ConcurrentHashMap");
        Class.forName("java.text.SimpleDateFormat");
        System.gc();
        Thread daemon = new Thread(() -> sleep(), "sample-daemon");
        daemon.setDaemon(true);
        daemon.start();
        Thread worker = new Thread(() -> sleep(), "sample-worker");
        worker.start();
        sleep();
    }

    private static void sleep() {
        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
