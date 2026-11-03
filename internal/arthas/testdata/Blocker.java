// Blocker starts one thread that holds a monitor and three threads that wait for it,
// so that "thread -b" has a blocking thread to report. Used by real_test.go.
public class Blocker {
    public static void main(String[] args) throws Exception {
        final Object lock = new Object();
        Thread holder = new Thread(new Runnable() {
            public void run() {
                synchronized (lock) {
                    try {
                        Thread.sleep(Long.MAX_VALUE);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }
        }, "lock-holder");
        holder.start();
        Thread.sleep(300);
        for (int i = 0; i < 3; i++) {
            new Thread(new Runnable() {
                public void run() {
                    synchronized (lock) {
                    }
                }
            }, "lock-waiter-" + i).start();
        }
        System.out.println("ready");
        Thread.sleep(Long.MAX_VALUE);
    }
}
