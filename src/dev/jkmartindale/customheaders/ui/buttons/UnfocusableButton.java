package dev.jkmartindale.customheaders.ui.buttons;

import javax.swing.*;

/**
 * {@code UnfocusableButton} is a {@code JButton} that isn't focusable. This is mostly useful for table controls where
 * the keyboard navigation is too messed up to be usable.
 */
public class UnfocusableButton extends JButton {
    /**
     * Creates an unfocusable button with text.
     *
     * @param text the text of the button
     */
    public UnfocusableButton(String text) {
        super(text);
        setFocusable(false);
    }
}
