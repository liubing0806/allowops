package demo;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.locks.LockSupport;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * State the stage-2 and stage-3 acceptance measurements put into the JVM before a call: more live threads,
 * optionally with deeper stacks and held monitors (for thread -b), and retained heap (for the old generation). Nothing here runs on the request
 * path of the load endpoints.
 */
@RestController
public class LoadController {
    private static final Object MONITOR = new Object();
    private static final List<Thread> THREADS = new ArrayList<>();
    private static final List<Object> RETAINED = new ArrayList<>();
    private static final List<Object> HELD = new ArrayList<>();

    /**
     * Starts n daemon threads that park. With blocked > 0, one of them holds a monitor and blocked of
     * them wait for it, so thread -b has a blocking thread to report. With depth > 0, every thread
     * first descends depth frames of {@link #down}; the first holders of the parked threads take a
     * monitor of their own every depth / locks frames on the way down and keep them while parked.
     */
    @GetMapping("/load/threads")
    public synchronized Map<String, Object> threads(@RequestParam int n, @RequestParam(defaultValue = "0") int blocked,
                                                    @RequestParam(defaultValue = "0") int depth, @RequestParam(defaultValue = "0") int holders,
                                                    @RequestParam(defaultValue = "0") int locks) throws InterruptedException {
        int start = THREADS.size();
        if (blocked > 0) {
            CountDownLatch held = new CountDownLatch(1);
            Thread holder = new Thread(() -> down(depth, 0, () -> {
                synchronized (MONITOR) {
                    held.countDown();
                    while (true) {
                        LockSupport.park();
                    }
                }
            }), "load-holder");
            start(holder);
            held.await();
            for (int i = 0; i < blocked; i++) {
                start(new Thread(() -> down(depth, 0, () -> {
                    synchronized (MONITOR) {
                        MONITOR.hashCode();
                    }
                }), "load-blocked-" + i));
            }
        }
        int lockEvery = locks > 0 && depth > 0 ? Math.max(1, depth / locks) : 0;
        for (int i = THREADS.size() - start, k = 0; i < n; i++, k++) {
            int every = k < holders ? lockEvery : 0;
            start(new Thread(() -> down(depth, every, () -> {
                while (true) {
                    LockSupport.park();
                }
            }), "load-parked-" + i));
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("started", THREADS.size() - start);
        m.put("total", THREADS.size());
        return m;
    }

    /**
     * Descends left frames, then runs bottom. With lockEvery > 0, every lockEvery-th frame takes a monitor of
     * its own and holds it for the frames below; the monitors are kept in HELD, so they escape and stay real.
     */
    private static void down(int left, int lockEvery, Runnable bottom) {
        if (left <= 0) {
            bottom.run();
            return;
        }
        if (lockEvery > 0 && left % lockEvery == 0) {
            Object m = new Object();
            synchronized (HELD) {
                HELD.add(m);
            }
            synchronized (m) {
                down(left - 1, lockEvery, bottom);
            }
        } else {
            down(left - 1, lockEvery, bottom);
        }
    }

    private static void start(Thread t) {
        t.setDaemon(true);
        t.start();
        THREADS.add(t);
    }

    /**
     * Keeps mb megabytes reachable, in arrays of size bytes. The default fills one 1 MB G1 region (the region size of a
     * 512 MB heap) with one humongous array, which goes to the old generation at once.
     */
    @GetMapping("/load/retain")
    public synchronized Map<String, Object> retain(@RequestParam int mb, @RequestParam(defaultValue = "1048512") int size) {
        long bytes = (long) mb << 20;
        long count = bytes / size;
        for (long i = 0; i < count; i++) {
            byte[] b = new byte[size];
            b[0] = (byte) i;
            RETAINED.add(b);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("arrays", count);
        m.put("total_arrays", RETAINED.size());
        return m;
    }
}
