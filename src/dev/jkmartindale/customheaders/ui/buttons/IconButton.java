package dev.jkmartindale.customheaders.ui.buttons;

import com.formdev.flatlaf.FlatLaf;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.net.URL;

// TODO: refactor a third time because Burp Suite switched to SVG icons

/**
 * {@code IconButton} is a {@code JLabel} that displays an icon meant to be interacted with using the mouse. Adjusts to
 * light/dark theme changes. Displays different icon states in response to {@code MouseEvent}.
 */
public class IconButton extends JLabel implements MouseListener {
    /**
     * Base URL for Burp Suite built-in icons.
     */
    static final String BURP_ICONS = "/resources/Media/";
    /**
     * Base URL for icons not found under {@code BURP_ICONS}.
     */
    static final String FALLBACK_ICONS = "/resources/dev/jkmartindale/customheaders/";
    /**
     * Whether this {@code IconButton} is using fallback icons or icons provided by Burp Suite.
     */
    boolean usingFallback;
    /**
     * Filename of the icon to use when the button is in a default state.
     */
    final String defaultIcon;
    /**
     * Filename of the icon to use when the button is in a hover state.
     */
    final String hoverIcon;
    /**
     * Filename of the icon to use when the button is in a pressed state.
     */
    final String pressedIcon;
    /**
     * Base URL for image resources to use with the current theme, either from Burp Suite built-in icons or fallback icons.
     */
    private String baseUrl;

    /**
     * Creates an {@code IconButton} with filenames for all three states.
     * @param defaultIcon filename for the default icon state
     * @param hoverIcon filename for the hover icon state
     * @param pressedIcon filename for the pressed icon state
     */
    public IconButton(String defaultIcon, String hoverIcon, String pressedIcon) {
        this.defaultIcon = defaultIcon;
        this.hoverIcon = hoverIcon;
        this.pressedIcon = pressedIcon;
        validateIcons();
        // Now that local variables are set, we can update the icons according to UI
        updateUI();
        addMouseListener(this);
    }

    /**
     * Checks if all icons for this {@code IconButton} are available from Burp Suite and switches to fallback icon
     * sources if needed. Fallbacks are applied for all states at once instead of just one missing state, to retain
     * cohesive icon states if Burp Suite ever changes the icon.
     */
    public void validateIcons() {
        URL[] paths = {
                getClass().getResource(BURP_ICONS + defaultIcon),
                getClass().getResource(BURP_ICONS + hoverIcon),
                getClass().getResource(BURP_ICONS + pressedIcon),
                getClass().getResource(BURP_ICONS + "dark/" + defaultIcon),
                getClass().getResource(BURP_ICONS + "dark/" + hoverIcon),
                getClass().getResource(BURP_ICONS + "dark/" + pressedIcon),
        };
        for (URL path : paths) {
            if (path == null) {
                usingFallback = true;
                System.err.println("Switching to fallback for icon " + defaultIcon);
                return;
            }
        }
        usingFallback = false;
    }

    /**
     * Action to run when the button is pressed. Override this in subclasses, or else no action will occur.
     */
    public void action() {
    }

    /**
     * Calls standard {@code JLabel} updates, then updates icon base URL to reflect light/dark theme and
     * Burp Suite/fallback status.
     */
    @Override
    public void updateUI() {
        super.updateUI();

        if (defaultIcon == null) {
            // Called by constructor in inheritance chain and not by local constructor, so ignore custom behavior
            return;
        }

        LookAndFeel laf = UIManager.getLookAndFeel();
        // Burp Suite's light theme icons look better with dark themes than the dark theme icons with light themes,
        // so assume light theme icons by default
        String baseUrl = usingFallback ? FALLBACK_ICONS : BURP_ICONS;
        if (laf instanceof FlatLaf) {
            baseUrl += ((FlatLaf) laf).isDark() ? "dark/" : "";
        }
        this.baseUrl = baseUrl;

        // Force redraw to ensure match with updated UI
        setState(IconState.DEFAULT);
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
            state = IconState.DEFAULT;
        }

        String url = baseUrl;
        switch (state) {
            case DEFAULT:
                url += defaultIcon;
                break;
            case HOVER:
                url += hoverIcon;
                break;
            case PRESSED:
                url += pressedIcon;
                break;
        }
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
        DEFAULT,
        /**
         * State of an icon when hovered over by a cursor.
         */
        HOVER,
        /**
         * State of an icon when the mouse button is pressed as the cursor hovers above.
         */
        PRESSED;
    }
}
