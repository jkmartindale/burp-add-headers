package dev.jkmartindale.customheaders.ui.buttons;

import javax.swing.*;
import java.awt.*;

/**
 * {@code CancelButton} is a button meant to be attached to {@code JDialog}s, closing the dialog when clicked.
 */
public class CancelButton extends JButton {
    /**
     * {@code Dialog} to close when this button is clicked.
     */
    private Dialog dialog;

    /**
     * Creates a Cancel button that closes the dialog when clicked.
     *
     * @param dialog the dialog to close when clicked
     */
    public CancelButton(Dialog dialog) {
        super("Cancel");
        this.dialog = dialog;
        addActionListener(e -> {
            dialog.setVisible(false);
            dialog.dispose();
        });
    }
}
