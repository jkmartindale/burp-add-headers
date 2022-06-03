package dev.jkmartindale.customheaders.ui.buttons;

import javax.swing.*;
import java.awt.*;
import java.net.URI;

/**
 * {@code HelpButton} is a clickable help icon that opens a documentation URI in the user's default web browser when
 * clicked.
 */
public class HelpButton extends IconButton {
    private URI uri = null;

    /**
     * Creates a {@code HelpButton} that opens {@code uri} in a web browser when clicked.
     *
     * @param uri URI to open in a web browser when clicked
     */
    public HelpButton(String uri) {
        super("help.png", "help_hover.png", "help_pressed.png");
        setToolTipText("RTFM");
        try {
            this.uri = new URI(uri);
        } catch (Exception e) {
            System.err.println("Could not parse URI: " + uri);
        }
    }

    /**
     * Opens the documentation URI in a browser, or displays an error dialog otherwise.
     */
    @Override
    public void action() {
        try {
            Desktop.getDesktop().browse(uri);
        } catch (Exception ex) {
            String message = ex.getMessage();
            JOptionPane.showMessageDialog(
                    // Spawn dialog in center of screen, not underneath button
                    SwingUtilities.getWindowAncestor(this),
                    // NullPointerException does not have a message
                    message != null ? message : "The documentation URL for this help button is invalid.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }
}
