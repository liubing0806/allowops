package demo;

import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.CommandLineRunner;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Ordinary endpoints used as the control group, plus /hot which drives HotService. */
@RestController
public class ApiController {
    private final HotService hot;
    private final ItemRepository items;

    public ApiController(HotService hot, ItemRepository items) {
        this.hot = hot;
        this.items = items;
    }

    @org.springframework.context.annotation.Bean
    CommandLineRunner seed() {
        return args -> {
            for (long i = 1; i <= 100; i++) {
                items.save(new Item(i, "item-" + i));
            }
        };
    }

    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }

    @GetMapping("/hot")
    public long hot(@RequestParam(defaultValue = "1") int calls) {
        long sum = 0;
        for (int i = 0; i < calls; i++) {
            sum += hot.work(i);
        }
        return sum;
    }

    /** CPU work plus a few KB of garbage, closer to a real handler than /ping. */
    @GetMapping("/work")
    public Map<String, Object> work(@RequestParam(defaultValue = "50") int iterations) {
        long h = 17;
        byte[] garbage = new byte[4096];
        for (int i = 0; i < iterations * 20; i++) {
            h = h * 31 + i;
            garbage[i & 4095] = (byte) h;
        }
        Map<String, Object> m = new HashMap<>();
        m.put("h", h);
        m.put("g", garbage[7]);
        return m;
    }

    @GetMapping("/db")
    public Item db(@RequestParam(defaultValue = "1") long id) {
        return items.findById(id % 100 + 1).orElse(null);
    }
}
