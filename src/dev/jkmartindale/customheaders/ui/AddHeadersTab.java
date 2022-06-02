package dev.jkmartindale.customheaders.ui;

import burp.AddHeaderSessionAction;
import dev.jkmartindale.customheaders.ui.buttons.HelpSettingsPanel;
import dev.jkmartindale.customheaders.ui.reusablepanels.BodyLabel;
import dev.jkmartindale.customheaders.ui.reusablepanels.TitleLabel;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * {@code AddHeadersTab} is the main view for the extension, a {@code JScrollPane} containing all the configuration UI
 * components.
 */
public class AddHeadersTab extends JScrollPane {
    /**
     * Burp Suite session handling action associated with this tab.
     */
    private final AddHeaderSessionAction action;

    /**
     * Creates a new {@code AddHeadersTab}.
     */
    public AddHeadersTab() {
        super();

        // Content panel
        JPanel contentPanel = new JPanel(new GridBagLayout() {{
            columnWidths = new int[]{0, 5, 0};
            rowHeights = new int[]{0, 5, 0, 5, 0};
        }});
        contentPanel.setBorder(new EmptyBorder(new Insets(10, 10, 30, 10)));

        // Contents
        contentPanel.add(new HelpSettingsPanel(), new GBConstraints()
                .grid(0, 0)
                .gridheight(5)
                .anchor(GBConstraints.FIRST_LINE_START));
        contentPanel.add(new TitleLabel("Add Headers"), new GBConstraints()
                .grid(2, 0)
                .anchor(GBConstraints.LINE_START));
        contentPanel.add(new BodyLabel("Define the in-scope targets for your current work. This configuration affects the behavior of tools throughout the suite. The easiest way to configure scope is to browse to your target and use the context menus in the site map to include or exclude URL paths."), new GBConstraints()
                .grid(2, 2)
                .fill(2)
                .anchor(GBConstraints.ABOVE_BASELINE_LEADING)
                .weightx(1.0));
        HeadersTablePanel tablePanel = new HeadersTablePanel();
        contentPanel.add(tablePanel, new GBConstraints()
                .grid(2, 4)
                .fill(2)
                .anchor(GBConstraints.NORTHWEST)
                .weightx(1.0));
        action = new AddHeaderSessionAction("Add Headers", tablePanel.getModel());

        // Wrapper
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(contentPanel, "North");

        // JScrollPane
        getHorizontalScrollBar().setUnitIncrement(25);
        getVerticalScrollBar().setUnitIncrement(25);
        setBorder(new EmptyBorder(0, 0, 0, 0));
        setViewportView(wrapper);
    }
}
