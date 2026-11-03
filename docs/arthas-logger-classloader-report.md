# Arthas `logger` 命令后类加载器不卸载的原因

状态：原因已查明。适用范围：Arthas 4.3.5；JDK 8u504 和 17.0.20.1；Spring Boot 2.7.18 示例应用的 logback 构建和 log4j2 构建。依据有三项：堆转储中从 GC 根到 `ArthasClassloader` 的引用链；不跟随该引用时的可达性分析；修改该引用的来源后的对照实验（第 4 节）。可选的处理方式见第 6 节。

- 对应：[arthas-stage2-acceptance-report.md](arthas-stage2-acceptance-report.md)（下称“验收报告”）3.4.2 节和第 5 节问题 1；`docs/java-diagnostics-arthas-plan.md` 决定 A69（`logger` 暂停）。
- 验证版本：测试代码为本报告所在分支中的版本；产品代码（`internal/`）与测量所用版本相同，本次没有改动。
- 原始数据：保存在执行测量的本地主机上，不进仓库。下文“原始数据”的路径都相对原始数据目录下的 `raw/` 和 `analysis/`。
- 测试代码：见第 8 节。

术语：

- `ArthasClassloader`：`com.taobao.arthas.agent.ArthasClassloader`，`URLClassLoader` 的子类。每次 attach 新建一个，加载 `arthas-core.jar` 中的 Arthas 类。
- 应用类加载器：示例应用为 Spring Boot 可执行 jar，应用的类由 `org.springframework.boot.loader.LaunchedURLClassLoader` 加载。它在 JVM 退出前不卸载。
- 辅助类：`logger` 命令定义到应用类加载器中的类，类名为 `com.taobao.arthas.core.command.logger.LogbackHelper` 或 `Log4j2Helper` 加上两个十六进制哈希。
- 保护域：`java.security.ProtectionDomain`。每个类都有一个保护域，由定义它的 `ClassLoader.defineClass` 调用指定。保护域对象有一个 `classloader` 字段。
- HPROF：`jcmd <pid> GC.heap_dump` 写出的堆转储格式。每个类有一条 CLASS DUMP 记录，其中单独列出该类的类加载器、父类、签名者和保护域。
- GC 根：垃圾回收器从这些引用开始判断对象是否存活，如线程对象、JNI 全局引用。
- Full GC：本报告中的 Full GC 都由 `jcmd <pid> GC.run` 触发，与验收报告相同。
- MiB：2^20 字节。

## 1. 结论

引用链（4 种组合相同，原始数据 `analysis/<svc>-logger.txt`）：

```
GC 根：线程对象（JDK 17 为 Catalina-utility-1，JDK 8 为 http-nio-8080-Acceptor）
  --[contextClassLoader]--> LaunchedURLClassLoader（应用类加载器）
  --[classes]--> java.util.ArrayList（JDK 8 为 java.util.Vector）
  --[elementData]--> Object[]
  --[第 8336 个元素等]--> 辅助类 com.taobao.arthas.core.command.logger.LogbackHelper654681d42dda6444
  --[保护域]--> java.security.ProtectionDomain
  --[classloader]--> com.taobao.arthas.agent.ArthasClassloader
```

1. `logger` 把辅助类定义到应用类加载器中，调用的是 `ReflectUtils.defineClass(类名, 字节码, 类加载器)`。这个三参数方法传给 `ClassLoader.defineClass` 的保护域是 `ReflectUtils` 类自己的保护域。`ReflectUtils` 由当次 attach 的 `ArthasClassloader` 加载，它的保护域的 `classloader` 字段指向这个 `ArthasClassloader`（第 5.1 节）。
2. 辅助类属于应用类加载器，应用类加载器不卸载，辅助类也不卸载。辅助类的保护域因此一直可达，`ArthasClassloader` 和它加载的类、它的对象也一直可达。
3. 辅助类名中含当次 `ArthasClassloader` 的哈希，每次调用都定义一个新的辅助类，不复用上一次的。所以每次 `logger` 调用留下一个 `ArthasClassloader`。
4. 不跟随辅助类到保护域的引用时，堆转储中 2 个 `ArthasClassloader` 都从 GC 根不可达（第 4.3 节）。
5. 对照实验：测试用 Arthas 变体只改动 `ReflectUtils.defineClass` 一处，不再用自己的保护域。在 JDK 8、17 和 logback、log4j2 的 4 种组合上，2 次 `logger` 调用、5 次 Full GC 后 `ArthasClassloader` 都卸载，元空间与 `version` 命令相同（第 4.4 节）。
6. 每次 `logger` 调用留下的资源：元空间 11.6~12.0 MiB，约 1850 个类，堆 2.0~3.0 MiB，直接内存 24 MiB（6 个 4 MiB 的 Netty 内存池块）。这些资源到 JVM 重启才释放（第 3、4.5 节）。
7. log4j2 示例应用上 `logger` 同样留下类加载器。此外 `logger` 在 log4j2 示例应用上返回 HTTP 500：Arthas 把结果序列化为 JSON 时出现 `StackOverflowError`。调用没有结果，类加载器同样留下（第 4.6 节）。
8. `logger` 的两个分支（列出日志级别、`--level` 修改级别）都调用同一个定义辅助类的方法。限制 `logger` 的选项不能避免这个问题。
9. 上游：Arthas 4.3.5 是 Maven Central 上的最新版本（2026-10-25）。GitHub `alibaba/arthas` master 分支上的 `LoggerCommand.java`、`ReflectUtils.java` 与 4.3.5 的源码相同。按 `logger classloader leak`、`ArthasClassloader metaspace`、`LogbackHelper` 搜索 GitHub issue，没有找到描述这个问题的 issue。

## 2. 环境与方法

### 2.1 环境

| 项 | 版本或配置 |
|---|---|
| 主机 | Linux 6.18.54-1-lts；Docker 29.8.2，Compose 5.6.0；Go 1.27.3 |
| JDK 镜像 | eclipse-temurin 8（1.8.0_504）、17（17.0.20.1）。镜像 `jvmarthas/app-logger:jdk8`（`sha256:50f42f5e…`）、`jvmarthas/app-logger:jdk17`（`sha256:c9cc2be6…`） |
| 示例应用 | `test/jvm-arthas/app`，Spring Boot 2.7.18。logback 构建：logback 1.2.12；log4j2 构建（`app/pom-log4j2.xml`）：log4j-core 2.17.2，没有 logback。堆 `-Xms512m -Xmx512m`，G1 |
| Arthas 文件 | 原版：`run/arthas-minlog`（4.3.5 的三个 jar、`logback.xml`、删除 MCP 两个键的 `arthas.properties`），与验收报告相同。测试用变体：`run/arthas-patched`（2.4 节） |
| 容器 | 内存限额 2 GiB，CPU 4~7；`ja-call` CPU 12~15。Compose 项目 `jvm-arthas-logger`，端口前缀 24 |

### 2.2 实验

`scripts/logger_leak.py` 对每种组合新建一个 JVM，步骤与验收报告的 `leak` 实验相同：

1. 预热请求，3 次 Full GC，记录基线。
2. 同一命令 2 次 `jvm_arthas` 调用（`ja-call`，即产品的 `jvmarthas.RunWith`）。每次调用新建状态目录。
3. 5 次 Full GC，间隔 2 秒，每次后记录元空间、已加载的类、堆和 cgroup 内存。
4. 类直方图（`GC.class_histogram`），类加载器列表（JDK 17 为 `VM.classloaders show-classes=true verbose=true`，JDK 8 为 `VM.classloader_stats` 和 `GC.class_stats ClassLoader,ClassName`）。
5. 堆转储（`GC.heap_dump`，只含存活对象，转储前 JVM 另做一次 Full GC）。

| 实验 | 服务 | 命令 | Arthas 文件 |
|---|---|---|---|
| `logger` | jdk8、jdk17（logback）；log4j2-8、log4j2-17（log4j2） | `logger` | 原版 |
| `logger` 的对照 | jdk8、jdk17 | `version` | 原版 |
| `logger-patched` | 与 `logger` 相同的 4 个服务 | `logger` | 测试用变体 |

每种组合 1 次运行。2 次调用足以区分“每次调用留下一个类加载器”和“只留下一个”。

### 2.3 堆转储分析

`scripts/hprof_paths.py` 读取 HPROF 文件，从 GC 根出发按广度优先搜索强引用，给出到每个目标对象的最短路径：

- 引用包括实例字段、对象数组元素、类的静态字段，以及 CLASS DUMP 记录中的类加载器、父类、签名者、保护域。
- `java.lang.ref.Reference` 子类的 `referent` 字段不跟随。`--follow-soft` 跟随 `SoftReference` 子类的 `referent`。
- `--exclude` 指定不跟随的引用，例如 `com.taobao.arthas.core.command.logger.LogbackHelper*:<protection domain>`，即名字以该前缀开头的类到其保护域的引用。
- `--kept` 统计只由被排除的引用保持的对象。

HPROF 不包含 `java.lang.Class` 对象的部分内部引用（如反射缓存 `reflectionData`）。脚本从 GC 根到达堆转储中 78~82% 的对象（第 7 节）。所以“不跟随某引用后不可达”在脚本的范围内成立；第 4.4 节的对照实验在真实 JVM 中验证同一结论，不依赖该脚本。

### 2.4 测试用 Arthas 变体

`scripts/patch-arthas-pd.sh` 从 Maven Central 下载 `arthas-common` 4.3.5 的源码 jar（核对 SHA-256），删除 `ReflectUtils.defineClass` 中两处“保护域为 null 时改用 `PROTECTION_DOMAIN`”的代码，编译后替换 `arthas-core.jar` 中的 `ReflectUtils` 类，写入 `run/arthas-patched`。脚本用 `javap` 核对编译出的类与原版的成员相同。替换后 `defineClass` 收到 null 时把 null 传给 `ClassLoader.defineClass`，`ClassLoader` 使用目标类加载器的默认保护域。这个变体只用于本次测试，不是可交付的文件。

## 3. 复现结果

2 次调用、5 次 Full GC 后与基线之差（原始数据 `analysis/summary.txt`）。元空间、类、堆来自示例应用的 `/diag`（MXBean），cgroup 内存为容器的 `memory.current`。

| 实验 | JDK | 日志框架 | 命令 | 调用结果 | 元空间 (MiB) | 已加载的类 | 卸载的类 | 堆 (MiB) | cgroup 内存 (MiB) | 类直方图中的 `ArthasClassloader` |
|---|---|---|---|---|---|---|---|---|---|---|
| `logger` | 8 | logback | `logger` | 2 次成功 | +28.9 | +4810 | 0 | +7.1 | +89.7 | 2 |
| `logger` | 17 | logback | `logger` | 2 次成功 | +30.8 | +4989 | 0 | +8.7 | +120.1 | 2 |
| `logger` | 8 | log4j2 | `logger` | 2 次失败（HTTP 500） | +28.6 | +4815 | 88 | +7.2 | +96.9 | 2 |
| `logger` | 17 | log4j2 | `logger` | 2 次失败（HTTP 500） | +30.7 | +5083 | 0 | +8.8 | +114.7 | 2 |
| 对照 | 8 | logback | `version` | 2 次成功 | +5.7 | +1120 | 3558 | +2.8 | +67.7 | 0 |
| 对照 | 17 | logback | `version` | 2 次成功 | +7.0 | +1295 | 3563 | +3.1 | +37.1 | 0 |
| `logger-patched` | 8 | logback | `logger` | 2 次成功 | +5.7 | +1127 | 3680 | +3.5 | +72.5 | 0 |
| `logger-patched` | 17 | logback | `logger` | 2 次成功 | +7.1 | +1306 | 3682 | +3.1 | +40.6 | 0 |
| `logger-patched` | 8 | log4j2 | `logger` | 2 次失败（HTTP 500） | +5.0 | +1026 | 3881 | +3.3 | +63.5 | 0 |
| `logger-patched` | 17 | log4j2 | `logger` | 2 次失败（HTTP 500） | +6.7 | +1379 | 3704 | +2.9 | +55.1 | 0 |

- 原版 `logger`：5 次 Full GC、类直方图和堆转储之后，元空间和已加载的类都没有减少，2 个 `ArthasClassloader` 都在。与验收报告 3.4.2 节一致。
- `version` 和测试用变体的 `logger`：第 3~5 次 Full GC 后卸载约 3560~3880 个类，`ArthasClassloader` 不在。
- log4j2-8 的 88 个卸载的类在第 1 次 Full GC 时卸载，之后不变；测试用变体上同样出现。这 88 个类的来源未查明；原版运行中 2 个 `ArthasClassloader` 仍在。

## 4. 证据

### 4.1 类加载器的内容

原始数据 `raw/logger/<svc>/logger/loaders-after.json`。

- JDK 17：`VM.classloaders` 中有 2 个 `ArthasClassloader`，各含 `LoggerCommand`、`LogbackHelper` 等 Arthas 类。`LaunchedURLClassLoader` 下有 2 个辅助类：`LogbackHelper28fb05f2dda6444`、`LogbackHelper654681d42dda6444`。
- JDK 8：`GC.class_stats` 中 `LaunchedURLClassLoader` 下有 2 个辅助类 `LogbackHelper318ce27d31cefde0`、`LogbackHelper75645ea931cefde0`。`VM.classloader_stats` 中 2 个 `ArthasClassloader` 各有 1845、1848 个类，块大小 11.34、11.36 MiB。
- 两个辅助类名的后 8 位（应用类加载器的哈希）相同，前一段（`ArthasClassloader` 的哈希）不同。每次调用定义了一个新的辅助类。

### 4.2 堆转储中的最短路径

原始数据 `analysis/<svc>-logger.txt`。4 个原版 `logger` 堆转储中，每个 `ArthasClassloader` 的最短路径都是第 1 节的 6 个引用。路径的最后两步：

| 堆转储 | 辅助类 | 辅助类的保护域 | 保护域的 `classloader` |
|---|---|---|---|
| JDK 17 logback | `LogbackHelper654681d42dda6444` | `ProtectionDomain @0xe06c7ee8` | `ArthasClassloader @0xe0572510` |
| JDK 17 logback | `LogbackHelper28fb05f2dda6444` | `ProtectionDomain @0xe0481670` | `ArthasClassloader @0xe0572aa8` |
| JDK 8 logback | `LogbackHelper75645ea931cefde0` | `ProtectionDomain @0xe1bae260` | `ArthasClassloader @0xe1bbc240` |
| JDK 8 logback | `LogbackHelper318ce27d31cefde0` | `ProtectionDomain @0xe15a88a8` | `ArthasClassloader @0xe1bbc788` |
| JDK 17 log4j2 | `Log4j2Helper79499ad22dda6444` | `ProtectionDomain @0xe094af68` | `ArthasClassloader @0xe09291a8` |
| JDK 17 log4j2 | `Log4j2Helper826fde52dda6444` | `ProtectionDomain @0xe07b9650` | `ArthasClassloader @0xe0929740` |
| JDK 8 log4j2 | `Log4j2Helper65d5e78a31cefde0` | `ProtectionDomain @0xe16ceff0` | `ArthasClassloader @0xe1639238` |
| JDK 8 log4j2 | `Log4j2Helper595371cb31cefde0` | `ProtectionDomain @0xe16cf040` | `ArthasClassloader @0xe1664418` |

辅助类的保护域与同一个 `ArthasClassloader` 加载的 Arthas 类的保护域是同一个对象。例如 JDK 17 中 `LoggerCommand @0xf3b30568` 和 `LogbackHelper28fb05f2dda6444` 的保护域都是 `@0xe0481670`（原始数据 `analysis/jdk17-logger-helpers-all.txt`）。

### 4.3 不跟随辅助类保护域时的可达性

原始数据 `analysis/<svc>-logger-exclude-helper-pd.txt`。第二种搜索不跟随名字以 `LogbackHelper`（log4j2 为 `Log4j2Helper`）开头的类到其保护域的引用，并跟随软引用。

| 堆转储 | 全部引用：到达的对象 / 总数 | `ArthasClassloader` 可达 | 不跟随辅助类保护域：到达的对象 | `ArthasClassloader` 可达 | 只由这些引用保持 |
|---|---|---|---|---|---|
| JDK 8 logback | 352 077 / 444 891 | 2 / 2 | 322 465 | 0 / 2 | 3804 个类，38 434 个实例和对象数组 |
| JDK 17 logback | 390 695 / 484 110 | 2 / 2 | 365 575 | 0 / 2 | 3811 个类，38 652 个实例和对象数组 |
| JDK 8 log4j2 | 359 851 / 459 272 | 2 / 2 | 327 305 | 0 / 2 | 3915 个类，41 277 个实例和对象数组 |
| JDK 17 log4j2 | 399 434 / 499 813 | 2 / 2 | 371 623 | 0 / 2 | 3925 个类，41 446 个实例和对象数组 |

- 在脚本覆盖的引用范围内，辅助类的保护域是 `ArthasClassloader` 从 GC 根可达的唯一原因。跟随软引用后仍不可达。
- 只由这些引用保持的类约 3800~3930 个，即 2 个 `ArthasClassloader` 的全部类（4.1 节每个约 1850 个）。实例中较多的有 `java.lang.String` 约 13 200~13 850 个、`com.taobao.text.Style$Composite` 5400 个、Netty 的 `PoolSubpage` 1276 个。

### 4.4 修改引用来源后的对照

测试用变体（2.4 节）下 4 种组合的结果见第 3 节表中 `logger-patched` 行。原始数据 `analysis/patched-<svc>-logger.txt`。

- 2 次 `logger` 调用、5 次 Full GC 后，4 个堆转储中都没有 `ArthasClassloader`，类直方图中也没有。
- 元空间 +5.0~+7.1 MiB，与同一 JDK 的 `version`（+5.7、+7.0 MiB）的差为 0.0~0.1 MiB（logback）。
- 辅助类仍在应用类加载器中（每个堆转储 2 个），它们的保护域的 `classloader` 字段指向 `LaunchedURLClassLoader`，即应用类加载器的默认保护域。
- 调用结果与原版相同：logback 上 2 次成功；log4j2 上 2 次 HTTP 500。

这个实验只改变辅助类的保护域，`ArthasClassloader` 就能卸载。结合 4.2、4.3 节，辅助类的保护域是 `logger` 后 `ArthasClassloader` 不卸载的原因。

### 4.5 每次调用留下的资源

| 资源 | JDK 8 | JDK 17 | 计算方法与原始数据 |
|---|---|---|---|
| 元空间 | 11.6 MiB（logback）、11.8 MiB（log4j2） | 11.9 MiB、12.0 MiB | （原版 `logger` − 对照）÷ 2；对照：logback 用 `version`，log4j2 用测试用变体 |
| 已加载的类 | 1845、1895 | 1847、1852 | 同上 |
| 堆（Full GC 后） | 2.2 MiB、2.0 MiB | 2.8 MiB、3.0 MiB | 同上 |
| 直接内存 | 24.0 MiB | 24.0 MiB | 见下 |
| cgroup 内存 | 11.0 MiB、16.7 MiB | 41.5 MiB、29.8 MiB | 同上；每种组合 1 次运行 |

直接内存（原始数据 `analysis/<svc>-logger-exclude-helper-pd.txt`）：

- 每个原版 `logger` 堆转储中，只由辅助类保护域保持的 `java.nio.DirectByteBuffer` 有 18 个：12 个容量 4 194 304 字节（4 MiB），6 个容量 0~5 字节。即每次调用 6 个 4 MiB 的块。这些块来自 Arthas 内置的 Netty 的内存池。
- JDK 17：这些缓冲区都有 cleaner，计入 `java.nio.Bits`。2 次 `logger` 后 `Bits.RESERVED_MEMORY` 为 48.08 MiB，`version` 和测试用变体为 0.08 MiB。JDK 9 起该计数器受 `-XX:MaxDirectMemorySize` 限制；对应用自身直接内存分配的影响未测。
- JDK 8：4 MiB 的缓冲区没有 cleaner，不计入 `java.nio.Bits`（2 次 `logger` 后 0.08 MiB）。每个 `ArthasClassloader` 中 Netty 的 `PlatformDependent.DIRECT_MEMORY_COUNTER` 为 25 166 065 字节（24.0 MiB）。
- JDK 17 每次调用的 cgroup 内存增量比 JDK 8 大 13~31 MiB，原因未测量。

### 4.6 log4j2 上的 HTTP 500

原始数据 `raw/log4j2-500/`。log4j2-17 上单独调用一次 `logger`，结果 `failed`，原因 `arthas exec: unexpected HTTP status 500 Internal Server Error`。目标容器内 Arthas 的日志 `arthas.log` 记录：

```
ERROR c.t.a.c.s.t.i.h.HttpRequestHandler -arthas process http request error: /api
java.lang.StackOverflowError: null
	at ...fastjson2.writer.FieldWriter.errorOnGet(FieldWriter.java:424)
	at ...fastjson2.writer.FieldWriterObject.writeInternal(FieldWriterObject.java:269)
	（以下为 fastjson2 写对象字段的递归）
```

- `jvm_arthas` 只使用 Arthas 的 HTTP API，结果以 JSON 返回。递归发生在把 `logger` 的结果写成 JSON 时。
- `Log4j2Helper` 在结果中放入了 log4j2 的 `LoggerConfig` 的 `config` 字段（Arthas 源码 `Log4j2Helper.doGetLoggerInfo`）。日志只记录了栈的前 256 行，引起递归的对象未查明。
- 辅助类在序列化之前已定义，所以调用失败后 `ArthasClassloader` 同样留下（第 3 节）。

## 5. 原因

### 5.1 源码

以下行号为 Maven Central 上 4.3.5 源码 jar 中的行号。`arthas-core.jar` 的字节码与之一致：`javap` 显示 `LoggerCommand` 调用三参数的 `ReflectUtils.defineClass`，`ReflectUtils.defineClass` 两处读取静态字段 `PROTECTION_DOMAIN`。

`arthas-core` 的 `LoggerCommand.java`：

```java
59  private static String arthasClassLoaderHash = ClassLoaderUtils
60          .classLoaderHash(LoggerCommand.class.getClassLoader());
...
289 private static Class<?> helperClassNameWithClassLoader(ClassLoader classLoader, Class<?> helperClass) {
290     String classLoaderHash = ClassLoaderUtils.classLoaderHash(classLoader);
291     String className = helperClass.getName();
293     String helperClassName = className + arthasClassLoaderHash + classLoaderHash;
296         return classLoader.loadClass(helperClassName);
299             byte[] helperClassBytes = AsmRenameUtil.renameClass(classToBytesMap.get(helperClass), ...);
301             return ReflectUtils.defineClass(helperClassName, helperClassBytes, classLoader);
```

`arthas-common` 的 `ReflectUtils.java`：

```java
86  protectionDomain = getProtectionDomain(ReflectUtils.class);   // 静态初始化，赋给 PROTECTION_DOMAIN
...
419 public static Class defineClass(String className, byte[] b, ClassLoader loader) throws Exception {
420     return defineClass(className, b, loader, null, null);
...
439     if (protectionDomain == null) {
440         protectionDomain = PROTECTION_DOMAIN;
...
443     c = (Class) unreflect.invoke(loader, className, b, 0, b.length, protectionDomain);
...
479     if (protectionDomain == null) {
480         protectionDomain = PROTECTION_DOMAIN;
```

- `loggers()`（列出）和 `level()`（`--level`）都调用 `helperClassNameWithClassLoader`。`loggers()` 对每个含 logback、log4j 或 log4j2 类的类加载器各定义一个辅助类。
- 辅助类名由辅助类原名、当次 `ArthasClassloader` 的哈希、目标类加载器的哈希组成。新的 attach 有新的 `ArthasClassloader`，`loadClass` 找不到上一次的辅助类，于是定义新的。
- `ReflectUtils` 由 `ArthasClassloader` 加载。`ArthasClassloader` 是 `URLClassLoader` 的子类，它为自己加载的类创建的保护域的 `classloader` 字段指向它自己（堆转储中 4.2 节的最后一步）。
- 4.3.5 源码中 `ReflectUtils.defineClass` 只有 `LoggerCommand` 一处调用（检索 `arthas-core`、`arthas-common` 源码）。其他 L1 命令不在目标应用的类加载器中定义类，这与验收报告中只有 `logger` 不卸载一致。

### 5.2 已排除的假设

| 假设 | 排除依据 |
|---|---|
| Arthas 的线程、会话或端口在清理后仍在 | 每次调用的清理结果为 `ok`；返回后没有监听端口，`arthas-` 线程为 0，进程与调用前相同（`calls.jsonl` 的 `post`）；4.3 节中不跟随一类引用后 `ArthasClassloader` 不可达；4.4 节中同样的清理流程下类加载器卸载 |
| Full GC 次数不够 | `version` 在第 3~4 次 Full GC 后卸载；原版 `logger` 在 5 次 Full GC、类直方图和堆转储之后仍在；测试用变体在同样条件下卸载 |
| 软引用保持，需要内存压力才释放 | 4.3 节跟随软引用后仍不可达 |
| 日志框架持有 Arthas 的对象（例如 Arthas 的 appender 加到了应用的 logback） | 4.2 节的路径中没有日志框架的对象；4.4 节只改辅助类的保护域就卸载 |
| JDK 8 的 `ClassLoader.domains`（类加载器记录的保护域集合）持有 Arthas 的保护域 | JDK 8u504 的 `java.lang.ClassLoader` 没有 `domains` 字段：反射列出的保护域相关字段只有 `defaultDomain` |

## 6. 可选的处理方式

| 方式 | 做法 | 效果 | 代价 | 状态 |
|---|---|---|---|---|
| A | 保持暂停（A69 现状） | 不出现本问题 | 不提供列出日志级别的功能 | 现状 |
| B | 恢复 `logger`，由 attach 次数上限（< 5）限制累计量 | 每次调用留下 4.5 节的资源，到 JVM 重启 | 见 6.2 | 资源量实测；恢复后的验收未做 |
| C1 | 使用自建的 `arthas-core.jar`，修改辅助类的保护域 | 实测 4 种组合下类加载器卸载（4.4 节） | 见 6.3 | 测试用变体实测；可交付的构建未做 |
| C2 | 向 Arthas 上游报告并提交修复，发布后使用官方 jar | 取决于上游的修复 | 发布时间不确定；需要负责人决定是否向上游提交 | 未提交 |
| D | 在清理步骤中解除引用 | — | 需要执行任意代码的命令，计划禁止 | 不可行，未测 |
| E | 不 attach，用其他方式列出日志级别 | 不加载 Arthas | 不通用，见 6.5 | 未测 |

### 6.1 A：保持暂停

不需要改动。计划第 4 节 L1 中 `logger` 的暂停说明可以把“原因查明前不提供”改为本报告的原因，由负责人决定。

### 6.2 B：恢复 `logger`

- 计划的 attach 次数上限为每个 JVM 生命周期 < 5 次。5 次都是 `logger` 时，按 4.5 节约为元空间 58~60 MiB、直接内存 120 MiB、堆 10~15 MiB，到 JVM 重启。验收报告 3.4.2 节实测 5 次 `logger` 后元空间 +63.7~+67.8 MiB。
- JDK 9 起直接内存计入 `-XX:MaxDirectMemorySize`。设置了较小上限的应用，可用于自身的直接内存减少 24 MiB × 调用次数；产品的执行前检查不检查直接内存。
- log4j2 应用（实测 2.17.2）上调用返回 HTTP 500，没有结果，资源同样留下（4.6 节）。产品在 attach 前不知道目标应用使用哪种日志框架。
- 验收报告项 4（50 次 attach/stop 后元空间 ≤ 基线 + 25 MB）在包含 `logger` 时未达到，恢复后仍为未达到。

### 6.3 C1：自建 `arthas-core.jar`

- 修改方式：测试用变体删除 `ReflectUtils.defineClass` 中保护域为 null 时的替换。按 5.1 节的检索，该方法在 4.3.5 中只有 `LoggerCommand` 调用，影响范围只有 `logger`。也可以只改 `LoggerCommand`，传入一个 `classloader` 为 null 的保护域；该做法未测。
- 剩余：每次调用仍在应用类加载器中留下一个辅助类，到 JVM 重启。2 次调用后比 `version` 多 7~11 个类，元空间多 0.0~0.1 MiB。
- 代价：
  - `arthas-core.jar` 不再是 Maven Central 的发布文件，SHA-256 改变。产品按固定文件和校验和分发 Arthas（`deploy/packaging/arthas/stage.py`），文件来源要改为自建，并维护构建和校验过程。
  - 每次升级 Arthas 都要重新修改、重新验证。
  - 测试用变体只核对了 `ReflectUtils` 的类成员与原版相同，只测了 `logger` 和第 3 节的指标，没有 Arthas 的其他回归测试。
  - log4j2 上的 HTTP 500 不受影响（4.4 节）。

### 6.4 D：在清理步骤中解除引用

- 引用位于类的保护域，HPROF 在 CLASS DUMP 记录中单独列出。JDK 8u504 和 17.0.20.1 的 `java.lang.Class` 反射列出的字段中都没有保存该类保护域的字段（JDK 8 只有静态字段 `allPermDomain`）。JDK 17 的反射屏蔽 `Class` 的部分字段（如 `classLoader`），这一核对不能排除被屏蔽的字段。
- 解除引用的两种途径都不可行：
  - 卸载辅助类：需要卸载应用类加载器。
  - 把该保护域对象的 `classloader` 字段（`final`）改为 null：需要在目标 JVM 中执行任意代码，Arthas 中能做到的是 `ognl`、`vmtool`、`groovy` 等命令，计划第 4 节禁止。该保护域同时是该次 attach 所有 Arthas 类的保护域（4.2 节），修改的影响未测。
- 结论：在计划允许的命令范围内不可行。未测。

### 6.5 E：不 attach 列出日志级别

| 途径 | 适用条件 | 限制 |
|---|---|---|
| Spring Boot Actuator 的 `/actuator/loggers`（HTTP） | 应用引入 Actuator 并暴露该端点 | 只适用于 Spring Boot 应用；Spring Boot 2.7 默认只通过 HTTP 暴露 `health`，示例应用没有暴露 `loggers`；端点的鉴权由应用决定；不属于 `jvm_arthas` |
| JMX | log4j2 2.24.0 之前默认注册 MBean，2.24.0 起默认关闭（`log4j2.disableJmx`，log4j2 官方文档）；logback 需要在配置中声明 `jmxConfigurator`；`java.util.logging` 的 `LoggingMXBean` 只覆盖 JUL | 读取需要目标 JVM 开启 JMX 端口，或通过 attach 启动本地 JMX 代理（`jcmd ManagementAgent.start_local`，也是 attach，但不加载 Arthas）；产品没有 JMX 客户端；Arthas 的 `mbean` 命令计划禁止 |
| 读取日志配置文件 | 能读到应用的 logback.xml、log4j2.xml 或 Spring 配置 | 只有配置的级别，看不到运行时修改后的级别 |

三种途径都未测。

### 6.6 建议（待负责人确认）

1. 保持 A69 的暂停（方式 A）。
2. 需要列出日志级别时，优先方式 C2：向上游报告本报告第 1、5 节的内容，发布后用官方 jar 按第 3 节的步骤复测。向上游提交属于对外发布，需要负责人决定。
3. 方式 B 不建议：log4j2 应用上调用失败且同样留下资源。

## 7. 局限

- 每种组合 1 次运行，每次运行 2 次调用。cgroup 内存的单次数据波动较大（4.5 节）。
- 分析脚本从 GC 根到达堆转储中 78~82% 的对象。JDK 17 原版 `logger` 堆转储中没有到达的 92 928 个对象以 `java.lang.String`（24 662 个）、`java.lang.reflect.Method`（8432 个）、`Class[]`、`LinkedHashMap$Entry`、`SoftReference`、`Class$ReflectionData`（2671 个）为主（原始数据 `analysis/jdk17-logger-unreached.txt`），与 HPROF 不包含的 `Class` 内部引用（反射缓存等）一致。4.3 节的结论在这一范围内成立；4.4 节的对照实验不依赖该脚本。
- log4j2 只测了 2.17.2 和 Spring Boot 的默认配置。log4j 1.x 未测：`Log4jHelper` 走同一个 `defineClass`，按源码会出现同样的问题，未验证。只使用 `java.util.logging` 的应用未测：按源码，没有检测到 logback、log4j、log4j2 时不定义辅助类。
- 应用中有多个含日志框架的类加载器（如外部 Tomcat 的多个 Web 应用）时未测。按源码，每个这样的类加载器各定义一个辅助类；辅助类所在的类加载器卸载时（如 Web 应用卸载），辅助类和它保持的 `ArthasClassloader` 才可能卸载，未验证。
- 只测了 JDK 8 和 17。验收报告中 JDK 11、21 的 `logger` 结果与 8、17 相同（3.4.2 节），本次未在 11、21 上取堆转储。
- HTTP 500 的递归对象未查明（4.6 节）。

## 8. 测试代码

在 `test/jvm-arthas/` 下：

| 文件 | 用途 |
|---|---|
| `compose.logger.yaml` | 与 `compose.yaml` 一起使用。jdk8、jdk17 使用自己的镜像标签；增加 log4j2-8、log4j2-17（profile `log4j2`），把 log4j2 构建挂载为 `/app/app.jar`；挂载 `run/arthas-patched` |
| `app/pom-log4j2.xml` | 示例应用的 log4j2 构建，输出到 `app/target-log4j2/` |
| `scripts/logger_leak.py` | 第 2.2 节的实验 |
| `scripts/hprof_paths.py` | 第 2.3 节的堆转储分析 |
| `scripts/patch-arthas-pd.sh` | 第 2.4 节的测试用 Arthas 变体 |

运行方式（在 `test/jvm-arthas` 下）：

```sh
make app probe arthas tools prepare
(cd app && mvn -q -s settings.xml -Dmaven.repo.local=../run/m2 -f pom-log4j2.xml clean package -DskipTests)
scripts/patch-arthas-pd.sh
mkdir -p run/log4j2-8/logs run/log4j2-17/logs && chmod 0777 run/log4j2-8/logs run/log4j2-17/logs
export COMPOSE_FILE=compose.yaml:compose.logger.yaml COMPOSE_PROJECT_NAME=jvm-arthas-logger JA_PORT_PREFIX=24 JA_OUT=<原始数据目录>/raw
docker compose build jdk8 jdk17
scripts/logger_leak.py --svcs jdk17,jdk8 --kinds logger,version --calls 2 --dump --name logger
scripts/logger_leak.py --svcs log4j2-17,log4j2-8 --kinds logger --calls 2 --dump --name logger
scripts/logger_leak.py --svcs jdk17,jdk8,log4j2-17,log4j2-8 --kinds logger --calls 2 --dump --flavor patched --name logger-patched
python3 -I scripts/hprof_paths.py <堆转储> --target com.taobao.arthas.agent.ArthasClassloader \
  --exclude 'com.taobao.arthas.core.command.logger.LogbackHelper*:<protection domain>' --follow-soft --kept
docker compose --profile jre --profile variants --profile log4j2 down -v --remove-orphans
```

`logger_leak.py` 调用 `ja-call`，需要 sudo（与验收报告的 `accept.py` 相同）。不需要运行 `make real-test`。
