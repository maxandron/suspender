package suspender

import kotlinx.cinterop.*
import platform.posix.*

fun hello(): String = "Hello, Kotlin/Native!"

fun main(args: Array<String>) {
    println(hello())

    if (args.size != 3 && args.size != 2) {
        println("Usage: ./suspender suspend <PID>")
        println("Usage: ./suspender load <dump file> <binary path>")
        exit(1)
    }

    if (args[0] == "suspend") {
        suspendPID(atoi(args[1]))
    } else if (args[0] == "load") {
        loadProgram(args[1], args[2])
    }
}

fun loadProgram(dumpFile: String, binaryPath: String) {
    val pid = fork()
//    when (pid) {
//        0 -> {
//            // Child
//            memScoped {
////                ptrace(PTRACE_TRACEME, 0, nativeNullPtr, nativeNullPtr)
////                exec(binaryPath.cstr.ptr.rawValue) // will automagically get a SIGTRAP signal
//            }
//        }
//        -1 -> exit(1) // Error
//        else -> {
//            // Parent
////            wait(nativeNullPtr)
//            val checkpointFile = fopen("/tmp/test", "w") ?: return
//            loadSegments(checkpointFile)
//        }
//    }
}

fun loadSegments(checkpointFile: CPointer<FILE>) {
    memScoped {
        val buffer = allocArray<ByteVar>(1)
        // Read header size
        fread(buffer, ByteVar.size.convert(), 1.convert(), checkpointFile)
    }
}

fun suspendPID(pid: Int) {
    kill(pid, SIGSTOP)

    val mappings = extractMappings(pid)

    val checkpointFile = fopen("/tmp/test", "w") ?: return
    val memoryFile = fopen("/proc/$pid/mem", "r") ?: return

    try {
        val mappingsRegex = "^([0-9a-z].*?)-([0-9a-z].*?) .* (.*)\$".toRegex()
        for (map in mappings.lines()) {
            val matches = mappingsRegex.find(map)
            if (matches != null) {
                val (startAddress, endAddress, mappingName) = matches.destructured
                saveSegment(checkpointFile, memoryFile, startAddress, endAddress, mappingName)
            }
        }
    } finally {
        fclose(checkpointFile)
        fclose(memoryFile)
    }
}

fun saveSegment(
    checkpointFile: CPointer<FILE>,
    memoryFile: CPointer<FILE>,
    startAddress: String,
    endAddress: String,
    mappingName: String
) {
    val segmentSize = strtol(endAddress, null, 16) - strtol(startAddress, null, 16)
    val headline = "$startAddress\t$endAddress\t$mappingName\t$segmentSize\n"
    fputs(headline, checkpointFile)
    memScoped {
        val memoryBuffer = allocArray<ByteVar>(segmentSize)
        fseek(memoryFile, segmentSize, SEEK_SET)
        fread(memoryBuffer, sizeOf<ByteVar>().convert(), segmentSize.convert(), memoryFile)
        fwrite(memoryBuffer, sizeOf<ByteVar>().convert(), segmentSize.convert(), checkpointFile)
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
