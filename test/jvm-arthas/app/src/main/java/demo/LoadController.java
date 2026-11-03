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
 * State the stage-2 acceptance measurements put into the JVM before a call: more live threads
 * (for thread -b) and retained heap (for the old generation). Nothing here runs on the request
 * path of the load endpoints.
 */
@RestController
public class LoadController {
    private static final Object MONITOR = new Object();
    private static final List<Thread> THREADS = new ArrayList<>();
    private static final List<Object> RETAINED = new ArrayList<>();

    /**
     * Starts n daemon threads that park. With blocked > 0, one of them holds a monitor and blocked of
     * them wait for it, so thread -b has a blocking thread to report.
     */
    @GetMapping("/load/threads")
    public synchronized Map<String, Object> threads(@RequestParam int n, @RequestParam(defaultValue = "0") int blocked) throws InterruptedException {
        int start = THREADS.size();
        if (blocked > 0) {
            CountDownLatch held = new CountDownLatch(1);
            Thread holder = new Thread(() -> {
                synchronized (MONITOR) {
                    held.countDown();
                    while (true) {
                        LockSupport.park();
                    }
                }
            }, "load-holder");
            start(holder);
            held.await();
            for (int i = 0; i < blocked; i++) {
                start(new Thread(() -> {
                    synchronized (MONITOR) {
                        MONITOR.hashCode();
                    }
                }, "load-blocked-" + i));
            }
        }
        for (int i = THREADS.size() - start; i < n; i++) {
            start(new Thread(() -> {
                while (true) {
                    LockSupport.park();
                }
            }, "load-parked-" + i));
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("started", THREADS.size() - start);
        m.put("total", THREADS.size());
        return m;
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
