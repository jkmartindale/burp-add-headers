package burp;

import dev.jkmartindale.customheaders.ui.AddHeadersTab;

import java.awt.*;
import java.io.PrintStream;

/**
 * Entry class the extension. Contains minimal logic to set up extension API callbacks and the extension tab, then
 * defers to other classes for implementation.
 */
public class BurpExtender implements IBurpExtender, ITab {
    /**
     * Static instance of Burp Extender callbacks.
     */
    private static IBurpExtenderCallbacks callbacks;

    /**
     * Root {@code Component} holding the extension tab UI.
     */
    Component tab;

    /**
     * This method is invoked when the extension is loaded. It registers an instance of the {@code
     * IBurpExtenderCallbacks} interface, providing methods that may be invoked by the extension to perform various
     * actions.
     *
     * @param callbacks An {@code IBurpExtenderCallbacks} object.
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Add Headers");
        BurpExtender.callbacks = callbacks;
        tab = new AddHeadersTab();
        callbacks.addSuiteTab(this);

        // Easier logging
        System.setOut(new PrintStream(callbacks.getStdout()));
        System.setErr(new PrintStream(callbacks.getStderr()));
    }

    /**
     * Burp uses this method to obtain the caption that should appear on the custom tab when it is displayed.
     *
     * @return The caption that should appear on the custom tab when it is displayed.
     */
    @Override
    public String getTabCaption() {
        return "Add Headers";
    }

    /**
     * Burp uses this method to obtain the component that should be used as the contents of the custom tab when it is
     * displayed.
     *
     * @return The component that should be used as the contents of the custom tab when it is displayed.
     */
    @Override
    public Component getUiComponent() {
        return tab;
    }

    /**
     * Returns the static instance of Burp Extender callbacks.
     * @return the static instance of Burp Extender callbacks
     */
    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }
}
