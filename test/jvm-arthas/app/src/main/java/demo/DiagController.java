package demo;

import java.lang.management.ClassLoadingMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Observation endpoints. They read only MXBeans and the thread group tree, so
 * reading them does not use the attach mechanism and does not need a safepoint.
 */
@RestController
public class DiagController {

    @GetMapping("/diag")
    public Map<String, Object> diag() {
        Map<String, Object> m = new LinkedHashMap<>();
        ThreadMXBean threads = ManagementFactory.getThreadMXBean();
        ClassLoadingMXBean classes = ManagementFactory.getClassLoadingMXBean();
        m.put("threads", threads.getThreadCount());
        m.put("classesLoaded", classes.getLoadedClassCount());
        m.put("classesTotalLoaded", classes.getTotalLoadedClassCount());
        m.put("classesUnloaded", classes.getUnloadedClassCount());
        long gcCount = 0;
        long gcMillis = 0;
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            gcCount += Math.max(0, gc.getCollectionCount());
            gcMillis += Math.max(0, gc.getCollectionTime());
        }
        m.put("gcCount", gcCount);
        m.put("gcMillis", gcMillis);
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if ("Metaspace".equals(pool.getName())) {
                m.put("metaspaceUsed", pool.getUsage().getUsed());
                m.put("metaspaceCommitted", pool.getUsage().getCommitted());
            } else if ("Compressed Class Space".equals(pool.getName())) {
                m.put("classSpaceUsed", pool.getUsage().getUsed());
                m.put("classSpaceCommitted", pool.getUsage().getCommitted());
            }
        }
        Runtime rt = Runtime.getRuntime();
        m.put("heapUsed", rt.totalMemory() - rt.freeMemory());
        m.put("uptimeMillis", ManagementFactory.getRuntimeMXBean().getUptime());
        m.put("spyApiLoaded", isBootstrapClassLoaded("java.arthas.SpyAPI"));
        return m;
    }

    /** Names of all live threads; with filter, only those containing the text (case-insensitive). */
    @GetMapping("/diag/threads")
    public List<String> threadNames(@RequestParam(defaultValue = "") String filter) {
        ThreadGroup root = Thread.currentThread().getThreadGroup();
        while (root.getParent() != null) {
            root = root.getParent();
        }
        Thread[] all = new Thread[root.activeCount() + 64];
        int n = root.enumerate(all, true);
        List<String> names = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String name = all[i].getName();
            if (filter.isEmpty() || name.toLowerCase().contains(filter.toLowerCase())) {
                names.add(name);
            }
        }
        return names;
    }

    /**
     * Whether the transformer chain currently registered in the JVM would rewrite the class with
     * Arthas spy calls. Needs the probe agent (-javaagent) and forces a retransform of the class.
     */
    @GetMapping("/diag/enhanced")
    public Map<String, Object> enhanced(@RequestParam(defaultValue = "demo.HotService") String cls) throws Exception {
        Map<String, Object> m = new LinkedHashMap<>();
        try {
            Class<?> probe = Class.forName("jvmprobe.Probe", true, ClassLoader.getSystemClassLoader());
            Object r = probe.getMethod("check", String.class).invoke(null, cls);
            m.put("result", r);
        } catch (ClassNotFoundException e) {
            m.put("error", "probe agent is not loaded");
        }
        return m;
    }

    private final HotService hot;

    public DiagController(HotService hot) {
        this.hot = hot;
    }

    /**
     * Calls HotService.work 200 times under a counting spy and reports whether the live bytecode
     * still calls into java.arthas.SpyAPI. Non-destructive; see LiveCheck.
     */
    @GetMapping("/diag/live")
    public Map<String, Object> live() {
        Map<String, Object> m = new LinkedHashMap<>();
        try {
            m.putAll(LiveCheck.run(() -> {
                for (int i = 0; i < 200; i++) {
                    hot.work(i);
                }
            }));
        } catch (Throwable t) {
            m.put("enhanced", false);
            m.put("spyApi", "absent: " + t.getClass().getSimpleName());
        }
        return m;
    }

    private static boolean isBootstrapClassLoaded(String name) {
        try {
            Class.forName(name, false, null);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }
}
