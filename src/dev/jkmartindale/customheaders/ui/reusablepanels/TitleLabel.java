package dev.jkmartindale.customheaders.ui.reusablepanels;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * {@code TitleLabel} is an encapsulated {@code JLabel} used as section titles throughout the Burp Suite interface.
 */
public class TitleLabel extends JPanel {
    /**
     * Creates a {@code TitleLabel} displaying {@text}.
     *
     * @param text text to display
     */
    public TitleLabel(String text) {
        super(new BorderLayout(20, 20));
        putClientProperty("html.disable", true);
        setBorder(new EmptyBorder(0, 0, 5, 0));
        setFocusable(false);

        add(new JLabel(text) {
            {
                putClientProperty("html.disable", true);
                setFocusable(false);
            }

            /**
             * Updates the font size and color when the pluggable UI changes.
             *
             * @see JComponent#updateUI
             */
            @Override
            public void updateUI() {
                super.updateUI();
                // JLabel#updateUI is overridden instead of overriding TitleLabel#updateUI,
                // since updateUI() calls seem to complete on parents before children.
                // A previous attempt using TitleLabel#updateUI was able to set fonts but not colors.
                setForeground(UIManager.getColor("Burp.burpTitle"));
                Font defaultFont = UIManager.getFont("Label.font");
                setFont(defaultFont.deriveFont(Font.BOLD, (float) Math.floor(defaultFont.getSize() * 1.2)));
            }
        }, "Center");
    }
}
