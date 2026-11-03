import com.sun.net.httpserver.HttpServer;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 * Target for the runtime that has no java.instrument module: embedded Tomcat itself needs
 * java.lang.instrument, so the Spring Boot sample cannot start on such a runtime.
 */
public class MiniServer {
    public static void main(String[] args) throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress(8080), 128);
        s.createContext("/ping", e -> reply(e, "pong"));
        s.createContext("/diag", e -> reply(e, "{\"threads\":" + ManagementFactory.getThreadMXBean().getThreadCount()
                + ",\"classesLoaded\":" + ManagementFactory.getClassLoadingMXBean().getLoadedClassCount() + "}"));
        s.start();
    }

    private static void reply(com.sun.net.httpserver.HttpExchange e, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        e.sendResponseHeaders(200, b.length);
        e.getResponseBody().write(b);
        e.close();
    }
}
