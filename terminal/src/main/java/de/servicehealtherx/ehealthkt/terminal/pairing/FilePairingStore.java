package de.servicehealtherx.ehealthkt.terminal.pairing;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * A {@link PairingStore} that persists pairing blocks to a JSON file. Loaded on construction and
 * rewritten on every change. (A TPM-protected variant can extend this by encrypting the bytes.)
 */
public class FilePairingStore extends InMemoryPairingStore {

    private static final Logger log = LoggerFactory.getLogger(FilePairingStore.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path file;

    public FilePairingStore(Path file) {
        this.file = file;
        load();
    }

    private void load() {
        if (!Files.exists(file)) {
            return;
        }
        try {
            PairingBlock[] loaded = MAPPER.readValue(Files.readAllBytes(file), PairingBlock[].class);
            blocks.addAll(List.of(loaded));
            log.info("Loaded {} pairing block(s) from {}", loaded.length, file);
        } catch (IOException e) {
            log.warn("Could not load pairing store {}", file, e);
        }
    }

    @Override
    public void add(PairingBlock block) {
        super.add(block);
        flush();
    }

    @Override
    public synchronized void flush() {
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            Files.write(file, MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(blocks));
        } catch (IOException e) {
            log.error("Could not persist pairing store {}", file, e);
        }
    }
}
