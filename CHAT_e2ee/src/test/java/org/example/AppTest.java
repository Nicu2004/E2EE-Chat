
package org.example;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class AppTest {

    @Test
    void helpCommandPrintsUsage() throws Exception {
        String text = runAndCaptureOutput("help");
        assertTrue(text.contains("Comenzi:"));
        assertTrue(text.contains("java -cp target/classes org.example.App server [port]"));
        assertTrue(text.contains("org.example.App authority-init"));
        assertTrue(text.contains("org.example.App authority-issue <nume>"));
    }

    @Test
    void helpCommandIsCaseInsensitive() throws Exception {
        assertTrue(runAndCaptureOutput("HELP").contains("Comenzi:"));
    }

    @Test
    void emptyArgumentsPrintUsage() throws Exception {
        assertTrue(runAndCaptureOutput().contains("Comenzi:"));
    }

    @Test
    void unknownRoleThrowsException() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> App.main(new String[] {"unknown"})
        );

        assertTrue(exception.getMessage().contains("Rol necunoscut"));
    }

    @Test
    void clientWithoutNameThrowsException() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> App.main(new String[] {"client"})
        );

        assertTrue(exception.getMessage().contains("Lipseste numele"));
    }

    @Test
    void serverWithNonNumericPortThrowsNumberFormatException() {
        assertThrows(NumberFormatException.class, () -> App.main(new String[] {"server", "abc"}));
    }

    @Test
    void clientWithNonNumericPortThrowsNumberFormatException() {
        assertThrows(NumberFormatException.class, () -> App.main(new String[] {"client", "Ana", "localhost", "abc"}));
    }

    private String runAndCaptureOutput(String... args) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        PrintStream capturedOut = new PrintStream(output, true, StandardCharsets.UTF_8);

        try {
            System.setOut(capturedOut);
            App.main(args);
        } finally {
            System.setOut(originalOut);
            capturedOut.close();
        }

        return output.toString(StandardCharsets.UTF_8);
    }
}
