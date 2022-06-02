package dev.jkmartindale.customheaders.ui.buttons;

import com.formdev.flatlaf.FlatLaf;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.net.URL;

/**
 * {@code IconButton} is a {@code JLabel} that displays an icon meant to be interacted with using the mouse. Adjusts to
 * light/dark theme changes. Displays different icon states in response to {@code MouseEvent}.
 */
public class IconButton extends JLabel implements MouseListener {
    /**
     * Base URL for image resources to use in light themes.
     */
    static final String LIGHT_URL = "/resources/Media/";
    /**
     * Base URL for image resources to use in dark themes.
     */
    static final String DARK_URL = "/resources/Media/dark/";
    /**
     * Base filename for image resources for this icon. Does not have file extension or directory path.
     */
    private final String baseIcon;
    /**
     * Base URL for image resources to use with the current theme. Gets set to either {@code LIGHT_URL} or {@code
     * DARK_URL} at runtime.
     */
    private String baseUrl;

    /**
     * Creates an {@code IconButton} with a given icon name.
     *
     * @param icon base filename for image resources for this icon. Do not include file extension or directory path.
     */
    public IconButton(String icon) {
        super();

        baseIcon = icon;
        addMouseListener(this);

        // Called here because baseIcon cannot be instantiated before first updateUI() call
        setState(IconState.DEFAULT);
    }

    /**
     * Action to run when the button is pressed. Override this in subclasses.
     */
    public void action() {
    }

    /**
     * Calls standard JLabel updates, then updates icon based on theme light/dark status.
     */
    @Override
    public void updateUI() {
        super.updateUI();

        // Set baseUrl based on theme light/dark status
        LookAndFeel laf = UIManager.getLookAndFeel();
        if (laf instanceof FlatLaf) {
            baseUrl = ((FlatLaf) laf).isDark() ? DARK_URL : LIGHT_URL;
        } else {
            // Wild guess that any non-FlatLaf L&Fs are more likely to be dark themes than light themes
            baseUrl = DARK_URL;
        }

        // The first updateUI() call comes before baseIcon is instantiated by the constructor
        if (baseIcon != null) {
            setState(IconState.DEFAULT);
        }
    }

    /**
     * Updates the icon's displayed image based off its state. {@code state} defaults to {@code IconState.DEFAULT} if
     * {@code null}. If the resulting icon URL ({@code baseUrl + baseIcon + state.suffix()} cannot be found, an error is
     * logged without throwing an exception.
     *
     * @param state state corresponding to the icon image to display.
     */
    private void setState(IconState state) {
        if (state == null) {
            System.err.println("IconButton.setState called with a null value, falling back to default.");
            state = IconState.DEFAULT;
        }

        String url = baseUrl + baseIcon + state.suffix();
        URL iconLocation = getClass().getResource(url);
        if (iconLocation == null) {
            System.err.printf("Could not find resource at URL %s.\n", url);
            return;
        }

        int size = getIconSize();
        Image image = new ImageIcon(iconLocation).getImage().getScaledInstance(size, size, Image.SCALE_SMOOTH);
        setIcon(new ImageIcon(image));
    }

    /**
     * Returns the size of {@code IconButton}s based on the current font size.
     *
     * @return size of {@code IconButton} to use.
     */
    private int getIconSize() {
        int fontSize;
        Font defaultFont = UIManager.getFont("defaultFont");
        if (defaultFont != null) {
            fontSize = UIManager.getFont("defaultFont").getSize();
        } else {
            fontSize = 13;
        }

        // For the life of me I can't figure out how this is calculated
        // 2/3 accuracy is the closest I got without hardcoding
        switch (fontSize) {
            case 9:
                return 16;
            case 13:
                return 24;
            case 14:
                return 27;
            case 17:
                return 31;
            case 18:
                return 33;
            case 28:
                return 51;
            default:
                return (int) ((int) (fontSize * 1.2) * 1.5);
        }
    }

    /**
     * Does not do anything, as visual changes are handled by {@code mousePressed()} and {@code mouseReleased()}.
     *
     * @param e the event to be processed
     */
    @Override
    public void mouseClicked(MouseEvent e) {
    }

    /**
     * Changes the icon to display in a pressed state.
     *
     * @param e the event to be processed
     */
    @Override
    public void mousePressed(MouseEvent e) {
        setState(IconState.PRESSED);
    }

    /**
     * Changes the icon to display in a hover state if the cursor is still hovering over the button.
     *
     * @param e the event to be processed
     */
    @Override
    public void mouseReleased(MouseEvent e) {
        if (contains(e.getPoint())) {
            setState(IconState.HOVER);
            action();
        }
    }

    /**
     * Changes the icon to display in a hover state.
     *
     * @param e the event to be processed
     */
    @Override
    public void mouseEntered(MouseEvent e) {
        setState(IconState.HOVER);
    }

    /**
     * Changes the icon to display in a default state.
     *
     * @param e the event to be processed
     */
    @Override
    public void mouseExited(MouseEvent e) {
        setState(IconState.DEFAULT);
    }

    /**
     * {@code IconState} represents the visual state of an icon.
     */
    private enum IconState {
        /**
         * Default state of an icon.
         */
        DEFAULT(".png"),
        /**
         * State of an icon when hovered over by a cursor.
         */
        HOVER("_hover.png"),
        /**
         * State of an icon when the mouse button is pressed as the cursor hovers above.
         */
        PRESSED("_pressed.png");

        /**
         * Suffix to add to {@code IconButton.baseIcon} to represent a full filename.
         */
        private final String _suffix;

        /**
         * Creates an {@code IconState} with a given filename/file extension suffix.
         */
        IconState(String suffix) {
            _suffix = suffix;
        }

        /**
         * Returns the suffix represented by this {@code IconState}.
         */
        public String suffix() {
            return _suffix;
        }
    }
}
