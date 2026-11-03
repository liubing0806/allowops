package demo;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.LockSupport;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * State the stage-3 checks of the L2 commands put into the JVM: CPU load for the CPU check before the attach and
 * for the guard, and calls of the overloaded methods of {@link L2Overloads}. Nothing here runs on the request path
 * of the load endpoints.
 */
@RestController
public class L2Controller {
    private static volatile long sink;
    private final L2Overloads overloads;

    public L2Controller(L2Overloads overloads) {
        this.overloads = overloads;
    }

    /**
     * Starts threads daemon threads that spin for seconds seconds and returns at once. Each thread is busy for duty percent
     * of every 10 ms and parks for the rest, so it uses about duty / 100 of one CPU.
     */
    @GetMapping("/l2/burn")
    public Map<String, Object> burn(@RequestParam int threads, @RequestParam int seconds, @RequestParam(defaultValue = "100") int duty) {
        final long end = System.nanoTime() + seconds * 1_000_000_000L;
        final long period = 10_000_000L;
        final long busy = period * Math.max(1, Math.min(100, duty)) / 100;
        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                long h = 1;
                while (System.nanoTime() < end) {
                    long p0 = System.nanoTime();
                    while (System.nanoTime() - p0 < busy) {
                        for (int k = 0; k < 1_000; k++) {
                            h = h * 6364136223846793005L + 1442695040888963407L;
                        }
                    }
                    if (busy < period) {
                        LockSupport.parkNanos(period - (System.nanoTime() - p0));
                    }
                }
                sink = h;
            }, "l2-burn-" + i);
            t.setDaemon(true);
            t.start();
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("threads", threads);
        m.put("seconds", seconds);
        m.put("duty", duty);
        return m;
    }

    /** Calls every overload of calc and many once. */
    @GetMapping("/l2/overloads")
    public long overloads(@RequestParam(defaultValue = "3") int x) {
        return overloads.calc(x) + overloads.calc((long) x) + overloads.many(x) + overloads.many((long) x)
                + overloads.many("s" + x) + overloads.many(x, x) + overloads.many((long) x, (long) x) + overloads.many((double) x);
    }
}
