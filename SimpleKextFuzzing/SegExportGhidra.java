// Exports memory segments and symbols in the format expected by the 
// Project Zero AppleAVD fuzzer loader.
// @category Fuzzing
// @author IntegralPilot

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;

import java.io.File;
import java.io.FileOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;
import java.util.ArrayList;
import java.util.List;

public class SegExportGhidra extends GhidraScript {

    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        if (program == null) {
            printerr("This script must be run with a program open.");
            return;
        }

        File outputFile = getOutputFile();
        if (outputFile == null) {
            println("Export cancelled.");
            return;
        }
        
        ByteArrayOutputStream fileContentStream = new ByteArrayOutputStream();

        exportMemoryAndSymbols(fileContentStream, program);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(fileContentStream.toByteArray());
        }
        
        println("\n[SUCCESS] Export complete: " + outputFile.getAbsolutePath());
    }

    private File getOutputFile() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 0) {
            File f = new File(args[0]);
            println("[INFO] Headless mode: Using output file from arguments: " + f.getAbsolutePath());
            return f;
        }
        return askFile("Select Output File", "Export");
    }

    private void writeLongLE(ByteArrayOutputStream stream, long value) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(value);
        stream.write(buffer.array());
    }

    private void exportMemoryAndSymbols(ByteArrayOutputStream stream, Program program) throws IOException {
        Memory memory = program.getMemory();

        List<MemoryBlock> initializedBlocks = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized()) {
                initializedBlocks.add(block);
            }
        }
        MemoryBlock[] blocks = initializedBlocks.toArray(new MemoryBlock[0]);
        Arrays.sort(blocks, Comparator.comparing(MemoryBlock::getStart));
        
        println("[INFO] Writing " + blocks.length + " segment headers (initialized only)...");
        writeLongLE(stream, blocks.length); 

        for (MemoryBlock block : blocks) {
            writeLongLE(stream, block.getStart().getOffset());
            writeLongLE(stream, block.getEnd().getOffset() + 1);
            long perms = (block.isRead() ? 4 : 0) | (block.isWrite() ? 2 : 0) | (block.isExecute() ? 1 : 0);
            writeLongLE(stream, perms);
        }
        println("[INFO] Segment headers written.");

        println("[INFO] Writing segment data...");
        for (MemoryBlock block : blocks) {
            try {
                byte[] data = new byte[(int)block.getSize()];
                block.getBytes(block.getStart(), data);
                stream.write(data);
            } catch (MemoryAccessException e) {
                printerr("[ERROR] Failed to read bytes from memory block: " + block.getName() + " - " + e.getMessage());
            }
        }
        println("[INFO] Segment data written.");
        
        println("[INFO] Preparing and writing symbol table...");
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);
        
        List<byte[]> symbolPayloads = new ArrayList<>();
        long totalSymbolPayloadSize = 0;
        
        while (symbols.hasNext() && !monitor.isCancelled()) {
            Symbol sym = symbols.next();
            
            if (sym.getSource() == SourceType.DEFAULT) continue;
            
            byte[] nameBytes = sym.getName().getBytes(StandardCharsets.UTF_8);
            long addr = sym.getAddress().getOffset();

            ByteBuffer entryBuffer = ByteBuffer.allocate(8 + nameBytes.length + 1);
            entryBuffer.order(ByteOrder.LITTLE_ENDIAN);
            entryBuffer.putLong(addr);
            entryBuffer.put(nameBytes);
            entryBuffer.put((byte) 0x00);
            
            byte[] finalEntry = entryBuffer.array();
            symbolPayloads.add(finalEntry);
            totalSymbolPayloadSize += finalEntry.length;
        }

        writeLongLE(stream, symbolPayloads.size());
        writeLongLE(stream, totalSymbolPayloadSize);

        for (byte[] payload : symbolPayloads) {
            stream.write(payload);
        }
        
        println("[INFO] Exported " + symbolPayloads.size() + " symbols.");
    }
}
