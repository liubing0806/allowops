package demo;

import org.springframework.stereotype.Service;

/**
 * The method that watch/trace/stack/monitor observe. One call is a fixed amount of
 * CPU work (about a microsecond), so the method's QPS equals the request QPS of
 * /hot multiplied by its calls parameter.
 */
@Service
public class HotService {
    public long work(int seed) {
        long h = seed;
        for (int i = 0; i < 200; i++) {
            h = h * 6364136223846793005L + 1442695040888963407L;
            h ^= h >>> 29;
        }
        return h;
    }
}
