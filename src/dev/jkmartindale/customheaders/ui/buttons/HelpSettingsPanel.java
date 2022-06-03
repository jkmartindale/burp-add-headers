package dev.jkmartindale.customheaders.ui.buttons;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * {@code HelpSettingsPanel} combines a help and settings button vertically into a single {@code JLabel}, ideal for
 * sticking next to a table control.
 */
public class HelpSettingsPanel extends JPanel {
    /**
     * Create a new {@code HelpSettingsPanel}.
     */
    public HelpSettingsPanel() {
        setBorder(new EmptyBorder(0, 0, 0, 5));
        setLayout(new GridLayout(2, 1, 0, 5));
        add(new HelpButton("https://github.com/jkmartindale/burp-add-headers"));
        add(new IconButton("settings.png", "settings_hover.png", "settings_pressed.png"));
    }
}
