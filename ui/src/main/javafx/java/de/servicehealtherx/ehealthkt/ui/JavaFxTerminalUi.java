package de.servicehealtherx.ehealthkt.ui;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.stage.Stage;

import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A JavaFX {@link TerminalUi} that simulates the terminal: a 2x16 monospace display, a numeric
 * keypad and a PIN field for host ("remote") PIN entry, plus a confirmation dialog.
 *
 * <p>Built only under the {@code -Pjavafx} Maven profile. {@link #requestPin} and {@link #confirm}
 * are blocking and may be called from any thread; UI mutations are marshalled onto the FX thread.
 */
public class JavaFxTerminalUi implements TerminalUi {

    private static final AtomicBoolean FX_STARTED = new AtomicBoolean(false);

    private final Label displayLine1 = new Label("");
    private final Label displayLine2 = new Label("");
    private final PasswordField pinField = new PasswordField();
    private final VBox pinPane;
    private final HBox confirmBar;
    private Stage stage;

    private final SynchronousQueue<char[]> pinResult = new SynchronousQueue<>();
    private final SynchronousQueue<Boolean> confirmResult = new SynchronousQueue<>();

    public JavaFxTerminalUi() {
        startToolkit();
        this.pinPane = buildPinPane();
        this.confirmBar = buildConfirmBar();
        runAndWait(this::buildStage);
    }

    private static void startToolkit() {
        if (FX_STARTED.compareAndSet(false, true)) {
            Platform.setImplicitExit(false);
            Platform.startup(() -> {
            });
        }
    }

    private void buildStage() {
        Font mono = Font.font("Monospaced", 18);
        displayLine1.setFont(mono);
        displayLine2.setFont(mono);
        VBox display = new VBox(2, displayLine1, displayLine2);
        display.setStyle("-fx-background-color: #173a17; -fx-text-fill: #b6ffb6; -fx-padding: 8;");
        displayLine1.setStyle("-fx-text-fill: #b6ffb6;");
        displayLine2.setStyle("-fx-text-fill: #b6ffb6;");

        pinPane.setVisible(false);
        confirmBar.setVisible(false);

        VBox root = new VBox(10, display, pinPane, confirmBar);
        root.setPadding(new Insets(12));
        root.setAlignment(Pos.TOP_CENTER);

        stage = new Stage();
        stage.setTitle("eHealth-KT");
        stage.setScene(new Scene(root, 320, 320));
        stage.show();
    }

    private VBox buildPinPane() {
        pinField.setEditable(false);
        pinField.setAlignment(Pos.CENTER);
        GridPane keypad = new GridPane();
        keypad.setHgap(6);
        keypad.setVgap(6);
        keypad.setAlignment(Pos.CENTER);
        String[] keys = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "C", "0", "OK"};
        for (int i = 0; i < keys.length; i++) {
            String key = keys[i];
            Button b = new Button(key);
            b.setMinSize(60, 48);
            b.setOnAction(e -> onKey(key));
            keypad.add(b, i % 3, i / 3);
        }
        Button cancel = new Button("Cancel");
        cancel.setOnAction(e -> submitPin(null));
        VBox pane = new VBox(8, pinField, keypad, cancel);
        pane.setAlignment(Pos.CENTER);
        return pane;
    }

    private HBox buildConfirmBar() {
        Button yes = new Button("Confirm");
        Button no = new Button("Cancel");
        yes.setOnAction(e -> submitConfirm(true));
        no.setOnAction(e -> submitConfirm(false));
        HBox bar = new HBox(12, yes, no);
        bar.setAlignment(Pos.CENTER);
        return bar;
    }

    private void onKey(String key) {
        switch (key) {
            case "C" -> pinField.clear();
            case "OK" -> submitPin(pinField.getText().toCharArray());
            default -> pinField.setText(pinField.getText() + key);
        }
    }

    private void submitPin(char[] pin) {
        pinPane.setVisible(false);
        pinField.clear();
        try {
            pinResult.put(pin == null ? new char[0] : pin);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void submitConfirm(boolean value) {
        confirmBar.setVisible(false);
        try {
            confirmResult.put(value);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void display(String line1, String line2) {
        Platform.runLater(() -> {
            displayLine1.setText(truncate(line1));
            displayLine2.setText(truncate(line2));
        });
    }

    @Override
    public char[] requestPin(PinRequest request) {
        Platform.runLater(() -> {
            displayLine1.setText(truncate(request.prompt()));
            displayLine2.setText("Slot " + request.slot());
            pinPane.setVisible(true);
        });
        try {
            char[] pin = pinResult.take();
            return pin.length == 0 ? null : pin;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    @Override
    public boolean confirm(String line1, String line2) {
        Platform.runLater(() -> {
            displayLine1.setText(truncate(line1));
            displayLine2.setText(truncate(line2));
            confirmBar.setVisible(true);
        });
        try {
            return confirmResult.take();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() > 16 ? s.substring(0, 16) : s;
    }

    private static void runAndWait(Runnable r) {
        if (Platform.isFxApplicationThread()) {
            r.run();
            return;
        }
        java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);
        Platform.runLater(() -> {
            try {
                r.run();
            } finally {
                latch.countDown();
            }
        });
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        if (stage != null) {
            Platform.runLater(stage::close);
        }
    }
}
