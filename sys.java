import java.io.File;
import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean; // Note: Works on standard Oracle/OpenJDK runtimes

public class SystemCheck {

    public static void main(String[] args) {
        System.out.println("=========================================");
        System.out.println("       STARTING SYSTEM DIAGNOSTIC        ");
        System.out.println("=========================================\n");

        checkOperatingSystem();
        checkCpuMetrics();
        checkMemoryMetrics();
        checkDiskSpace();

        System.out.println("=========================================");
        System.out.println("         SYSTEM CHECK COMPLETED          ");
        System.out.println("=========================================");
    }

    /**
     * Checks basic OS and environment metadata.
     */
    private static void checkOperatingSystem() {
        System.out.println("[1] OPERATING SYSTEM INFO");
        System.out.println("    OS Name:    " + System.getProperty("os.name"));
        System.out.println("    OS Version: " + System.getProperty("os.version"));
        System.out.println("    OS Arch:    " + System.getProperty("os.arch"));
        System.out.println("    Java Ver:   " + System.getProperty("java.version"));
        System.out.println();
    }

    /**
     * Checks CPU availability and processing load.
     */
    private static void checkCpuMetrics() {
        System.out.println("[2] CPU METRICS");
        Runtime runtime = Runtime.getRuntime();
        System.out.println("    Available Processors (Cores): " + runtime.availableProcessors());
        
        try {
            OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
            double systemCpuLoad = osBean.getCpuLoad() * 100;
            double processCpuLoad = osBean.getProcessCpuLoad() * 100;
            
            System.out.printf("    Total System CPU Load:        %.2f%%\n", systemCpuLoad);
            System.out.printf("    JVM Process CPU Load:         %.2f%%\n", processCpuLoad);
        } catch (Exception e) {
            System.out.println("    CPU Load Metrics:             Unavailable on this JVM platform");
        }
        System.out.println();
    }

    /**
     * Measures JVM heap memory usage.
     */
    private static void checkMemoryMetrics() {
        System.out.println("[3] JVM MEMORY USAGE");
        Runtime runtime = Runtime.getRuntime();
        
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long maxMemory = runtime.maxMemory();
        long usedMemory = totalMemory - freeMemory;

        final long MB = 1024 * 1024;

        System.out.println("    Used Memory:  " + (usedMemory / MB) + " MB");
        System.out.println("    Free Memory:  " + (freeMemory / MB) + " MB");
        System.out.println("    Total Heap:   " + (totalMemory / MB) + " MB");
        System.out.println("    Max Heap Configured: " + (maxMemory / MB) + " MB");
        System.out.println();
    }

    /**
     * Evaluates storage thresholds for the root partition.
     */
    private static void checkDiskSpace() {
        System.out.println("[4] DISK STORAGE CHECK");
        File root = new File("/");
        
        long totalSpace = root.getTotalSpace();
        long freeSpace = root.getFreeSpace();
        long usableSpace = root.getUsableSpace();

        final long GB = 1024 * 1024 * 1024;

        System.out.println("    Total Space:  " + (totalSpace / GB) + " GB");
        System.out.println("    Free Space:   " + (freeSpace / GB) + " GB");
        System.out.println("    Usable Space: " + (usableSpace / GB) + " GB");
        
        // Basic Alert Rule logic
        if (usableSpace < (5 * GB)) {
            System.out.println("    WARNING: Usable disk space is below 5 GB!");
        } else {
            System.out.println("    Storage Status: HEALTHY");
        }
        System.out.println();
    }
}
