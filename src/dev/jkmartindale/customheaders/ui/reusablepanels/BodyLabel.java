package dev.jkmartindale.customheaders.ui.reusablepanels;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.DefaultCaret;
import java.awt.*;

/**
 * {@code BodyLabel} represents paragraph body text in various parts of Burp Suite. Unfortunately {@code JLabel} doesn't
 * support line wrapping, which is why this is based on {@code JTextArea}.
 */
public class BodyLabel extends JTextArea {
    /**
     * Creates a new {@code BodyLabel} containing {@code text}.
     *
     * @param text text to display
     */
    public BodyLabel(String text) {
        putClientProperty("html.disable", true);
        setText(text);
        setOpaque(false);
        setBorder(new EmptyBorder(0, 0, 10, 0));
        setEditable(false);
        setLineWrap(true);
        setWrapStyleWord(true);
    }

    /**
     * Returns the preferred size of the TextArea. This is the maximum of the size needed to display the text and the
     * size requested for the viewport.
     *
     * @return the size
     */
    @Override
    public Dimension getPreferredSize() {
        return new Dimension(100, super.getPreferredSize().height);
    }

    /**
     * Ensures text selection stays disabled when the pluggable UI is reloaded/changed.
     *
     * @see JComponent#updateUI
     */
    @Override
    public void updateUI() {
        super.updateUI();

        // Hat tip to https://stackoverflow.com/a/32515501/3427178
        setHighlighter(null);
        setCaret(new DefaultCaret() {
            /**
             * Disables (logical) selection by setting the mark equal to the dot. This does not disable text highlighting.
             *
             * @return the position &gt;= 0
             * @see DefaultCaret#getMark
             */
            @Override
            public int getMark() {
                return getDot();
            }
        });
    }
}
