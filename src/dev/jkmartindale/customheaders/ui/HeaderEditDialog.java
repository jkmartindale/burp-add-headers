package dev.jkmartindale.customheaders.ui;

import dev.jkmartindale.customheaders.model.CustomHeader;
import dev.jkmartindale.customheaders.ui.buttons.CancelButton;
import dev.jkmartindale.customheaders.ui.reusablepanels.BodyLabel;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.function.Function;

/**
 * {@code HeaderEditDialog} is a modal dialog that enables adding or editing a new header. Instead of exposing a public
 * constructor, {@code HeaderEditDialog} provides static methods {@link #add(HeadersTablePanel)} and {@link #edit} to
 * build the appropriate dialog.
 */
public class HeaderEditDialog extends JDialog {
    /**
     * Table panel with the model to add headers to. The model reference can't be saved directly because at
     * instantiation time {@code panel.getModel()} may be null.
     */
    private HeadersTablePanel panel;
    /**
     * Text field containing the header name.
     */
    private JTextField name = new JTextField();
    /**
     * Text field containing the header value prefix.
     */
    private JTextField prefix = new JTextField();
    /**
     * Text field containing the header value.
     */
    private JTextField value = new JTextField();

    /**
     * Creates a modal header editor dialog that manages a header in the specified {@code HeadersTablePanel}.
     *
     * @param panel    the {@code HeadersTablePanel} to add/edit a header for
     * @param title    the title of the dialog
     * @param okAction the action for the OK button to perform, returning true if the dialog should close afterward
     * @throws IllegalArgumentException if the {@code panel} isn't a child of a {@link Dialog} or {@link Frame}
     * @throws IllegalArgumentException if the {@code panel}'s {@code GraphicsConfiguration} isn't from a screen device
     * @throws HeadlessException        when {@code GraphicsEnvironment.isHeadless()} returns {@code true}
     * @see GraphicsEnvironment#isHeadless
     * @see JComponent#getDefaultLocale
     */
    private HeaderEditDialog(HeadersTablePanel panel, String title, Function<HeaderEditDialog, Boolean> okAction) {
        super(SwingUtilities.getWindowAncestor(panel), title, ModalityType.DOCUMENT_MODAL);
        this.panel = panel;

        JPanel contentPanel = new JPanel(new GridBagLayout() {{
            columnWidths = new int[]{0, 5, 0};
            rowHeights = new int[]{0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0};
        }});
        contentPanel.setBorder(new EmptyBorder(15, 15, 15, 15));

        contentPanel.add(
                new BodyLabel("Specify a header name and value. Optionally, a prefix can be added to the value."),
                new GBConstraints()
                        .grid(0, 0)
                        .gridwidth(3)
                        .fill(GBConstraints.HORIZONTAL)
                        .anchor(GBConstraints.ABOVE_BASELINE_LEADING)
                        .weightx(1.0)
        );

        // Only needs to be set for one JTextField for layout purposes
        name.setColumns(30);

        contentPanel.add(name, new GBConstraints()
                .grid(2, 2)
                .fill(GBConstraints.HORIZONTAL)
                .anchor(GBConstraints.ABOVE_BASELINE_LEADING)
        );
        contentPanel.add(prefix, new GBConstraints()
                .grid(2, 4)
                .fill(GBConstraints.HORIZONTAL)
                .anchor(GBConstraints.ABOVE_BASELINE_LEADING)
        );
        contentPanel.add(value, new GBConstraints()
                .grid(2, 6)
                .fill(GBConstraints.HORIZONTAL)
                .anchor(GBConstraints.ABOVE_BASELINE_LEADING)
        );
        contentPanel.add(new JLabel("Header Name:"), new GBConstraints()
                .grid(0, 2)
                .anchor(GBConstraints.ABOVE_BASELINE_LEADING)
        );
        contentPanel.add(new JLabel("Value Prefix:"), new GBConstraints()
                .grid(0, 4)
                .anchor(GBConstraints.ABOVE_BASELINE_LEADING)
        );
        contentPanel.add(new JLabel("Header Value:"), new GBConstraints()
                .grid(0, 6)
                .anchor(GBConstraints.ABOVE_BASELINE_LEADING)
        );
        contentPanel.add(new JLabel("error"), new GBConstraints()
                .grid(2, 8)
                .anchor(GBConstraints.FIRST_LINE_START));
        // TODO: tooltip
        contentPanel.add(new JButton("Paste Item"), new GBConstraints()
                .grid(0, 10)
                .anchor(GBConstraints.NORTHWEST)
                .insets(15, 0, 0, 0)
                .weighty(1.0)
        );

        JPanel buttonPanel = new JPanel(new GridLayout(1, 2, 5, 0));
        buttonPanel.add(new JButton("OK") {
            {
                addActionListener(e -> {
                    if (okAction.apply(HeaderEditDialog.this)) {
                        HeaderEditDialog.this.setVisible(false);
                        HeaderEditDialog.this.dispose();
                    }
                });
            }
        });
        buttonPanel.add(new CancelButton(this));
        contentPanel.add(buttonPanel, new GBConstraints()
                .grid(2, 10)
                .anchor(GBConstraints.NORTHEAST)
                .insets(15, 0, 0, 0)
                .weighty(1.0)
        );

        getContentPane().add(contentPanel, "Center");
        pack(); // First pack() call doesn't properly calculate button size
        pack(); // Wow, I really hate Swing !!!
        setLocationRelativeTo(SwingUtilities.getWindowAncestor(panel));
    }

    /**
     * Creates a {@code HeaderEditDialog} for adding a new header.
     *
     * @param panel panel containing the table to add a header to
     * @return new {@code HeaderEditDialog} ready to add a new header
     */
    public static HeaderEditDialog add(HeadersTablePanel panel) {
        return new HeaderEditDialog(panel, "Add header creation rule", dialog -> {
            String nameStripped = dialog.name.getText().strip();
            if (nameStripped.equals("")) {
                return false;
            }

            dialog.panel.getModel().addHeader(
                    new CustomHeader(true, nameStripped, dialog.prefix.getText(), dialog.value.getText())
            );
            return true;
        });
    }

    /**
     * Creates a {@code HeaderEditDialog} for editing an existing header.
     *
     * @param panel panel containing the table to add a header to
     * @param index model row index of the header to update
     * @return new {@code HeaderEditDialog} populated with values from the old header at {@code index}
     */
    public static HeaderEditDialog edit(HeadersTablePanel panel, int index) {
        CustomHeader header = panel.getModel().getHeader(index);

        HeaderEditDialog editDialog = new HeaderEditDialog(panel, "Edit header creation rule", dialog -> {
            String nameStripped = dialog.name.getText().strip();
            if (nameStripped.equals("")) {
                return false;
            }

            dialog.panel.getModel().setHeader(index,
                    new CustomHeader(header.isEnabled(), nameStripped, dialog.prefix.getText(), dialog.value.getText())
            );
            return true;
        });

        editDialog.name.setText(header.getName());
        editDialog.prefix.setText(header.getPrefix());
        editDialog.value.setText(header.getValue());

        return editDialog;
    }
}
