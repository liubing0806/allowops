package demo;

import java.arthas.SpyAPI;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Answers "does the live bytecode of HotService.work still call java.arthas.SpyAPI?" without
 * touching the class: a counting spy replaces the current one for the length of the body, the
 * method is called, and the previous spy is put back. A retransform is never triggered, so an
 * enhancement that was left behind is observed instead of repaired.
 * Needs arthas-spy.jar on the bootstrap path, i.e. Arthas was attached at least once.
 */
final class LiveCheck {
    private LiveCheck() {
    }

    static Map<String, Object> run(Runnable body) {
        Counting c = new Counting();
        SpyAPI.AbstractSpy previous = SpyAPI.getSpy();
        boolean wasNop = SpyAPI.isNopSpy();
        SpyAPI.setSpy(c);
        try {
            body.run();
        } finally {
            SpyAPI.setSpy(previous);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("previousSpyWasNop", wasNop);
        m.put("atEnter", c.enter);
        m.put("atExit", c.exit);
        m.put("atExceptionExit", c.exceptionExit);
        m.put("atBeforeInvoke", c.beforeInvoke);
        m.put("atLine", c.line);
        m.put("enhanced", c.enter + c.exit + c.exceptionExit + c.beforeInvoke + c.line > 0);
        return m;
    }

    private static final class Counting extends SpyAPI.AbstractSpy {
        volatile long enter;
        volatile long exit;
        volatile long exceptionExit;
        volatile long beforeInvoke;
        volatile long line;

        @Override
        public void atEnter(Class<?> clazz, String methodInfo, Object target, Object[] args) {
            enter++;
        }

        @Override
        public void atExit(Class<?> clazz, String methodInfo, Object target, Object[] args, Object returnObject) {
            exit++;
        }

        @Override
        public void atExceptionExit(Class<?> clazz, String methodInfo, Object target, Object[] args, Throwable throwable) {
            exceptionExit++;
        }

        @Override
        public void atBeforeInvoke(Class<?> clazz, String invokeInfo, Object target) {
            beforeInvoke++;
        }

        @Override
        public void atAfterInvoke(Class<?> clazz, String invokeInfo, Object target) {
        }

        @Override
        public void atInvokeException(Class<?> clazz, String invokeInfo, Object target, Throwable throwable) {
        }

        @Override
        public void atLine(Class<?> clazz, String methodInfo, int lineNumber, Object target, Object[] args,
                String[] argNames, Object[] localVars, String[] localVarNames) {
            line++;
        }
    }
}
