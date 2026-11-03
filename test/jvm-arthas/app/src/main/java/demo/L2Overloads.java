package demo;

import org.springframework.stereotype.Service;

/**
 * Overloaded methods for the stage-3 checks of the L2 commands: an enhancement of calc affects 2 methods
 * (more than max_methods 1), one of many affects 6 (more than the default max_methods, 5). Only the
 * /l2/overloads endpoint calls them.
 */
@Service
public class L2Overloads {
    public long calc(int x) {
        return x * 31L;
    }

    public long calc(long x) {
        return x * 37L;
    }

    public long many(int x) {
        return x + 1L;
    }

    public long many(long x) {
        return x + 2L;
    }

    public long many(String x) {
        return x.length() + 3L;
    }

    public long many(int x, int y) {
        return x + y + 4L;
    }

    public long many(long x, long y) {
        return x + y + 5L;
    }

    public long many(double x) {
        return (long) x + 6L;
    }
}
