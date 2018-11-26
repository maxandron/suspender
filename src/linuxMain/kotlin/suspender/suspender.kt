package suspender

import kotlinx.cinterop.*
import platform.linux.Elf64_WordVar
import platform.linux.user_regs_struct
import platform.posix.*

const val DEFAULT_PID = "11413"
const val DEFAULT_DUMP = "/tmp/suspender.dump"
const val DEFAULT_BINARY = "/home/maxandron/work/CTFs/digimon/digimon_nowait"
const val CURRENT_MODE = "load"

fun main(args_temp: Array<String>) {
    val args = arrayOf("program", CURRENT_MODE)

    if (args.size != 2) {
        println("Usage:\t./suspender save")
        println("\t\t./suspender load")
        exit(1)
    }

    if (args[1] == "save") {
        suspendProgram(atoi(DEFAULT_PID), DEFAULT_DUMP)
    } else if (args[1] == "load") {
        loadProgram(DEFAULT_DUMP, DEFAULT_BINARY)
    }
}

fun error(message: String) {
    println("$message\n")
    exit(1)
}

fun loadProgram(dumpFileName: String, binaryPath: String) {
    val child = fork()
    when (child) {
        0 -> { // Child
            if (-1 == setpgid(0, 0)) {
                error("child set process group id failed")
            }

            ptrace(PTRACE_TRACEME, 0, 0, 0)
            execv(binaryPath, cValuesOf<ByteVar>()) // will automagically get a SIGTRAP signal
        }
        -1 -> error("Fork failed") // Error
        else -> {
            // Parent
            if (-1 == waitpid(-1, cValuesOf(0), 0)) {
                error("parent waitpid failed")
            }
            val dumpFile = fopen(dumpFileName, "rb") ?: return
            try {
                loadSegments(dumpFile, child)
                // Restore the process
                ptrace(PTRACE_CONT, child, SIGCONT, 0)
                if (SIG_ERR == signal(SIGTTOU, SIG_IGN)) {
                    error("ignoring SIGTTOU failed")
                }
                if (-1 == tcsetpgrp(0, child)) {
                    error("parent setting foreground process group failed")
                }
                if (SIG_ERR == signal(SIGTTOU, SIG_DFL)) {
                    error("restoring default signaling failed")
                }

                if (-1 == waitpid(child, cValuesOf(0), 0)) {
                    error("parent waiting for child to exit failed")
                }

                if (-1 == waitpid(child, cValuesOf(0), 0)) {
                    error("parent waiting for child to exit failed")
                }
            } finally {
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
            if (amountRead != 1.convert<size_t>()) break

            amountRead = fread(buffer.ptr, LongVar.size.convert(), 1.convert(), dumpFile)
            val segmentEnd = buffer.value
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
    for (address in segmentStart..segmentEnd step Elf64_WordVar.size) {
        ptrace(PTRACE_POKEDATA, pid, address, data[address - segmentStart])
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
        val mappingsRegex = "^([0-9a-z].*?)-([0-9a-z].*?) rw.*".toRegex()
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
        kill(pid, SIGCONT)
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

    printf("saving segment from %#10x to %#10x ($segmentSize)\n", startAddress, endAddress)

    memScoped {
        val memoryBuffer = allocArray<Elf64_WordVar>(segmentSize)
        fseek(memoryFile, startAddress, SEEK_SET)
        val amountRead = fread(memoryBuffer, Elf64_WordVar.size.convert(), segmentSize.convert(), memoryFile)
        printf("Read $amountRead bytes\n")
        if (amountRead.toLong() != segmentSize) {
            printf("skipping section\n")
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
