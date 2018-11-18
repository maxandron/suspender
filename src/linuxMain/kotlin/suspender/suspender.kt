package suspender

import kotlinx.cinterop.*
import platform.posix.*

const val DEFAULT_PID = "3555"
const val DEFAULT_DUMP = "/tmp/suspender.dump"
const val DEFAULT_BINARY = "/home/maxandron/work/CTFs/digimon/digimon_nowait"

fun main(args_temp: Array<String>) {
    val args = arrayOf("program", "load")

    if (args.size != 2) {
        println("Usage: ./suspender suspend")
        println("Usage: ./suspender load")
        exit(1)
    }

    if (args[1] == "suspend") {
        suspendProgram(atoi(DEFAULT_PID), DEFAULT_DUMP)
    } else if (args[1] == "load") {
        loadProgram(DEFAULT_DUMP, DEFAULT_BINARY)
    }
}

fun loadProgram(dumpFile: String, binaryPath: String) {
    val pid = fork()
    when (pid) {
        0 -> {
            // Child
            memScoped {
                ptrace(PTRACE_TRACEME, 0, nativeNullPtr, nativeNullPtr)
//                exec(binaryPath.cstr.ptr.rawValue) // will automagically get a SIGTRAP signal
            }
        }
        -1 -> exit(1) // Error
        else -> {
            // Parent
//            wait(nativeNullPtr)
            val checkpointFile = fopen("/tmp/test", "w") ?: return
            loadSegments(checkpointFile)
        }
    }
}

fun loadSegments(checkpointFile: CPointer<FILE>) {
    memScoped {
        val buffer = allocArray<ByteVar>(1)
        // Read header size
        fread(buffer, ByteVar.size.convert(), 1.convert(), checkpointFile)
    }
}

fun suspendProgram(pid: Int, dumpFileName: String) {
    // Suspend the process
    kill(pid, SIGSTOP)
    waitpid(pid, null, 0)

    val mappings = extractMappings(pid)

    val dumpFile = fopen(dumpFileName, "w") ?: return
    val memoryFile = fopen("/proc/$pid/mem", "rb") ?: return

    try {
        val mappingsRegex = "^([0-9a-z].*?)-([0-9a-z].*?) .*".toRegex()
        for (map in mappings.lines()) {
            val matches = mappingsRegex.find(map)
            if (matches != null) {
                val (startAddress, endAddress) = matches.destructured
                saveSegment(
                    dumpFile, memoryFile,
                    strtol(startAddress, null, 16),
                    strtol(endAddress, null, 16)
                )
            }
        }
    } finally {
        fclose(dumpFile)
        fclose(memoryFile)
    }
}

fun saveSegment(
    dumpFile: CPointer<FILE>,
    memoryFile: CPointer<FILE>,
    startAddress: Long,
    endAddress: Long
) {
    val segmentSize = endAddress - startAddress

    if (0L == segmentSize) {
        return
    }

    println("saving segment from $startAddress to $endAddress ($segmentSize)")

    // Write header (<startAddress> <endAddress>, <segmentSize>)
    fwrite(cValuesOf(startAddress), LongVar.size.convert(), 1.convert(), dumpFile)
    fwrite(cValuesOf(endAddress), LongVar.size.convert(), 1.convert(), dumpFile)
    fwrite(cValuesOf(segmentSize), LongVar.size.convert(), 1.convert(), dumpFile)

    memScoped {
        val memoryBuffer = allocArray<ByteVar>(segmentSize)
        fseek(memoryFile, startAddress, SEEK_SET)
        val amountRead = fread(memoryBuffer, ByteVar.size.convert(), segmentSize.convert(), memoryFile)
        println("Read $amountRead bytes")
        fwrite(memoryBuffer, ByteVar.size.convert(), segmentSize.convert(), dumpFile)
    }
}

private fun extractMappings(pid: Int): StringBuilder {
    val mapsFd = fopen("/proc/$pid/maps", "r")
    try {
        val mappings = StringBuilder()
        memScoped {
            val bufferLength = 64 * 1024
            val buffer = allocArray<ByteVar>(bufferLength)
            while (true) {
                val line = fgets(buffer, bufferLength, mapsFd)?.toKString()
                if (line == null || line.isEmpty()) {
                    break
                }
                mappings.append(line)
            }
        }
        return mappings
    } finally {
        fclose(mapsFd)
    }
}
