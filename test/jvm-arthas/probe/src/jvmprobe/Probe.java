package jvmprobe;

import java.io.FileOutputStream;
import java.io.PrintStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Test-only java agent, loaded with -javaagent at JVM start. It gives a JDK-independent record of
 * retransformations (JDK 8 has no -Xlog:redefine+class) and can ask "would the transformers that are
 * registered right now rewrite this class with Arthas spy calls?".
 */
public final class Probe {
    private static final byte[] SPY = "java/arthas/SpyAPI".getBytes();
    private static volatile Instrumentation inst;
    private static volatile PrintStream log = System.err;

    private Probe() {
    }

    public static void premain(String args, Instrumentation instrumentation) throws Exception {
        inst = instrumentation;
        String file = args == null || args.isEmpty() ? "/logs/probe.log" : args;
        try {
            log = new PrintStream(new FileOutputStream(file, true), true);
        } catch (Exception e) {
            log = System.err;
        }
        // Registered first, so it sees the original bytes of every retransformation.
        instrumentation.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader l, String name, Class<?> redefined, ProtectionDomain pd, byte[] b) {
                if (redefined != null && name != null && name.startsWith("demo/")) {
                    log.println(System.currentTimeMillis() + " RETRANSFORM " + name + " in=" + b.length);
                }
                return null;
            }
        }, true);
        log.println(System.currentTimeMillis() + " PROBE started");
    }

    /** Registers an observer after all other transformers, retransforms the class, reports the final bytes. */
    public static Map<String, Object> check(String className) throws Exception {
        final Class<?> target = Class.forName(className, false, ClassLoader.getSystemClassLoader());
        final String internal = className.replace('.', '/');
        final int[] outLen = {-1};
        final boolean[] seenSpy = {false};
        final int[] calls = {0};
        ClassFileTransformer observer = new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader l, String name, Class<?> redefined, ProtectionDomain pd, byte[] b) {
                if (redefined == target && internal.equals(name)) {
                    calls[0]++;
                    outLen[0] = b.length;
                    seenSpy[0] = indexOf(b, SPY) >= 0;
                }
                return null;
            }
        };
        inst.addTransformer(observer, true);
        try {
            inst.retransformClasses(target);
        } finally {
            inst.removeTransformer(observer);
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("class", className);
        r.put("observerCalls", calls[0]);
        r.put("finalBytes", outLen[0]);
        r.put("containsSpyApi", seenSpy[0]);
        log.println(System.currentTimeMillis() + " CHECK " + className + " containsSpyApi=" + seenSpy[0]);
        return r;
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i <= hay.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
