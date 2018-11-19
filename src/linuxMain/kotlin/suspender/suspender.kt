package suspender

import kotlinx.cinterop.*
import platform.linux.Elf64_WordVar
import platform.posix.*

const val DEFAULT_PID = "6983"
const val DEFAULT_DUMP = "/tmp/suspender.dump"
const val DEFAULT_BINARY = "/home/maxandron/work/CTFs/digimon/digimon_nowait"
const val CURRENT_MODE = "load"

fun main(args_temp: Array<String>) {
    val args = arrayOf("program", CURRENT_MODE)

    if (args.size != 2) {
        println("Usage:\t./suspender suspend")
        println("\t\t./suspender load")
        exit(1)
    }

    if (args[1] == "suspend") {
        suspendProgram(atoi(DEFAULT_PID), DEFAULT_DUMP)
    } else if (args[1] == "load") {
        loadProgram(DEFAULT_DUMP, DEFAULT_BINARY)
    }
}

fun loadProgram(dumpFileName: String, binaryPath: String) {
    val pid = fork()
    when (pid) {
        0 -> {
            // Child
            memScoped {
                ptrace(PTRACE_TRACEME, 0, 0, 0)
                execv(binaryPath, cValuesOf<ByteVar>()) // will automagically get a SIGTRAP signal
            }
        }
        -1 -> exit(1) // Error
        else -> {
            // Parent
            waitpid(-1, cValuesOf(0), 0)
            val dumpFile = fopen(dumpFileName, "rb") ?: return
            try {
//                ptrace(PTRACE_ATTACH, pid, 0, 0)
                loadSegments(dumpFile, pid)
            } finally {
                // Restore the process
//                ptrace(PTRACE_DETACH, pid, 0, 0)
                kill(pid, SIGCONT)
                fclose(dumpFile)
            }
        }
    }
}

fun loadSegments(dumpFile: CPointer<FILE>, pid: Int) {
    memScoped {
        while (true) {
            val buffer = alloc<LongVar>()

            var amountRead = fread(buffer.ptr, LongVar.size.convert(), 1.convert(), dumpFile)
            val segmentStart = buffer.value
            println("Segment start = $segmentStart")
            if (amountRead != 1.convert<size_t>()) break

            amountRead = fread(buffer.ptr, LongVar.size.convert(), 1.convert(), dumpFile)
            val segmentEnd = buffer.value
            println("Segment end = $segmentEnd")
            if (amountRead != 1.convert<size_t>()) break

            val segmentSize = segmentEnd - segmentStart
            val dataBuffer = allocArray<Elf64_WordVar>(segmentSize)
            amountRead = fread(dataBuffer, Elf64_WordVar.size.convert(), segmentSize.convert(), dumpFile)
            if (amountRead != (segmentEnd - segmentStart).convert<size_t>()) break

            loadSegment(pid, segmentStart, segmentEnd, dataBuffer)
        }
    }
}

fun loadSegment(pid: Int, segmentStart: Long, segmentEnd: Long, data: CArrayPointer<Elf64_WordVar>) {
//    val segmentSize = segmentEnd - segmentStart
//    val memoryFile = fopen("/proc/$pid/mem", "rb") ?: return
//
//    try {
//        fseek(memoryFile, segmentStart, 0)
//        val amountWrote = fwrite(data, ByteVar.size.convert(), segmentSize.convert(), memoryFile)
//        println("Wrote $amountWrote / $segmentSize")
//        if (amountWrote != segmentSize.convert<size_t>()) {
//            println("Failed writing segment $segmentStart:$segmentEnd")
//        }
//    } finally {
//        fclose(memoryFile)
//    }

    for (address in segmentStart..segmentEnd step Elf64_WordVar.size) {
        val testPtrace = ptrace(PTRACE_POKEDATA, pid, address, data[address - segmentStart])
        if (-1L == testPtrace) {
            println("Failed writing at $address")
        }
    }
}

fun suspendProgram(pid: Int, dumpFileName: String) {
    // Suspend the process
    kill(pid, SIGSTOP)
    waitpid(pid, null, 0)

    val mappings = extractMappings(pid)

    val dumpFile = fopen(dumpFileName, "wb") ?: return
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

    memScoped {
        val memoryBuffer = allocArray<Elf64_WordVar>(segmentSize)
        fseek(memoryFile, startAddress, SEEK_SET)
        val amountRead = fread(memoryBuffer, Elf64_WordVar.size.convert(), segmentSize.convert(), memoryFile)
        println("Read $amountRead bytes")
        if (amountRead.toLong() != segmentSize) {
            println("skipping section")
            return
        }

        fwrite(cValuesOf(startAddress), LongVar.size.convert(), 1.convert(), dumpFile)
        fwrite(cValuesOf(endAddress), LongVar.size.convert(), 1.convert(), dumpFile)
        fwrite(memoryBuffer, Elf64_WordVar.size.convert(), segmentSize.convert(), dumpFile)
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
