package dev.jkmartindale.customheaders.ui.reusablepanels;

import javax.swing.*;
import javax.swing.border.AbstractBorder;
import javax.swing.border.Border;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.plaf.basic.BasicSplitPaneUI;
import java.awt.*;

/**
 * Despite being derived from {@code JSplitPane}, {@code RightExpandablePane} is only meant to hold a {@code Component}
 * to the left. The "split pane" is used as an easy implementation of a container that can expand its contents to the
 * right. This copies the container used by Burp Suite for some of their table widgets.
 */
public class RightExpandablePane extends JSplitPane {
    /**
     * Creates a new {@code RightExpandablePane} containing a single {@code Component} to the left that can expand into
     * space to the right.
     */
    public RightExpandablePane() {
        setRightComponent(new JPanel());
        setDividerSize(10);
        setBorder(null);
        setOpaque(false);
    }

    /**
     * Notification from the {@code UIManager} that the L&amp;F has changed. Replaces the current UI object with the
     * latest version from the {@code UIManager}. Sets the pane divider to an arrow pointing right, indicating that the
     * panel can be expanded.
     *
     * @see JComponent#updateUI
     */
    @Override
    public void updateUI() {
        super.updateUI();
        setUI(new ExpandablePaneUI());
    }
}

/**
 * {@code ExpandablePaneUI} is slightly modified {@code BasicSplitPaneUI} using an arrow pointing right for its divider,
 * indicating that the panel can be expanded.
 */
class ExpandablePaneUI extends BasicSplitPaneUI {
    /**
     * Creates a divider with an arrow pointing right, indicating that the panel can be expanded.
     *
     * @return the divider
     */
    @Override
    public BasicSplitPaneDivider createDefaultDivider() {
        return new BasicSplitPaneDivider(this) {
            /**
             * Sets the border to an arrow pointing right, indicating that the panel can be expanded.
             * @param border unused
             */
            @Override
            public void setBorder(final Border border) {
                super.setBorder(new AbstractBorder() {
                    /**
                     * Paints a triangle pointing to the right to indicate that the left {@code Component} can be resized.
                     *
                     * @param c      the component for which this border is being painted (unused)
                     * @param g      the paint graphics
                     * @param x      the x position of the painted border (unused)
                     * @param y      the y position of the painted border (unused)
                     * @param width  the width of the painted border
                     * @param height the height of the painted border
                     */
                    @Override
                    public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
                        g.setColor(UIManager.getColor("Burp.burpTitle"));
                        g.fillPolygon(
                                new int[]{2, 2, width},
                                new int[]{(height - width) / 2, (height + width) / 2, height / 2},
                                3
                        );
                    }
                });
            }
        };
    }
}
