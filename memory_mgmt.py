from burp import IBurpExtender, IExtensionStateListener
import java.lang.management.ManagementFactory
import java.lang.management.MemoryMXBean

class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Memory Management")
        callbacks.registerExtensionStateListener(self)

        memory_bean = java.lang.management.ManagementFactory.getMemoryMXBean()
        self.increase_memory(memory_bean)

    def increase_memory(self, memory_bean):
        memory_pool = memory_bean.getNonHeapMemoryUsage()
        max_memory = memory_pool.getMax()
        increased_memory = max_memory * 1.5

        if increased_memory <= 0:
            increased_memory = int(1.5 * memory_pool.getCommitted())
        
        runtime = java.lang.Runtime.getRuntime()
        runtime.maxMemory = increased_memory

    def extensionUnloaded(self):
        memory_bean = java.lang.management.ManagementFactory.getMemoryMXBean()
        self.cleanup_memory(memory_bean)

    def cleanup_memory(self, memory_bean):
        memory_pool = memory_bean.getNonHeapMemoryUsage()
        max_memory = memory_pool.getMax()
        original_memory = max_memory / 1.5

        if original_memory <= 0:
            original_memory = int(memory_pool.getCommitted() / 1.5)

        runtime = java.lang.Runtime.getRuntime()
        runtime.maxMemory = original_memory
        runtime.gc()
