package dev.jkmartindale.customheaders.ui;

import dev.jkmartindale.customheaders.model.HeadersTableModel;
import dev.jkmartindale.customheaders.ui.buttons.UnfocusableButton;
import dev.jkmartindale.customheaders.ui.reusablepanels.RightExpandablePane;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;

/**
 * {@code HeadersTablePanel} displays the table of header addition rules as well as the buttons to add/edit/remove
 * them.
 */
public class HeadersTablePanel extends JPanel {
    /**
     * Table model managing header rule data to display. This is stored separately from the {@code JTable} because
     * subclass methods are used by {@link HeaderEditDialog}.
     */
    private HeadersTableModel model;

    /**
     * Creates a new {@code HeadersTablePanel}.
     */
    public HeadersTablePanel() {
        setLayout(new GridBagLayout() {{
            columnWidths = new int[]{0, 5, 0};
            rowHeights = new int[]{0, 5, 0, 5, 0, 5, 0, 5, 0};
        }});
        setFocusable(false);

        model = new HeadersTableModel();
        JTable table = new JTable(model) {{
            setDefaultRenderer(Boolean.class, new BooleanCellRenderer());
            setAutoCreateRowSorter(true);
        }};
        model.updateColumnWidths(table);

        JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(table);

        RightExpandablePane pane = new RightExpandablePane() {{
            setDividerLocation(7 * 80);
            setLeftComponent(scrollPane);
        }};
        add(pane, new GBConstraints()
                .grid(2, 0)
                .gridheight(9)
                .fill(GBConstraints.BOTH)
                .weightx(1.0));

        add(new UnfocusableButton("Add") {{
            setToolTipText("Add a new item");
            addActionListener(e -> {
                HeaderEditDialog.add(HeadersTablePanel.this).setVisible(true);
            });
        }}, new GBConstraints()
                .grid(0, 0)
                .fill(GBConstraints.HORIZONTAL)
                .anchor(GBConstraints.NORTHWEST));
        add(new UnfocusableButton("Edit") {{
            setToolTipText("Edit the selected item");
            addActionListener(e -> {
                HeaderEditDialog.edit(
                        HeadersTablePanel.this,
                        table.convertRowIndexToModel(table.getSelectedRow())
                ).setVisible(true);
            });
        }}, new GBConstraints()
                .grid(0, 2)
                .fill(GBConstraints.HORIZONTAL)
                .anchor(GBConstraints.NORTHWEST));
        add(new UnfocusableButton("Remove") {{
            setToolTipText("Remove the selected items");
            addActionListener(e -> {
                HeadersTablePanel.this.model.removeHeaders(
                        Arrays.stream(table.getSelectedRows()).map((int row) -> table.convertRowIndexToModel(row)).toArray()
                );
            });
        }}, new GBConstraints()
                .grid(0, 4)
                .fill(GBConstraints.HORIZONTAL)
                .anchor(GBConstraints.NORTHWEST));

        JButton pasteButton = new UnfocusableButton("Paste Item");
        pasteButton.setToolTipText("Add a new item by pasting a header: value combination");
//        pasteButton.addActionListener(new eoe(this));
        add(pasteButton, new GBConstraints()
                .grid(0, 6)
                .fill(GBConstraints.HORIZONTAL)
                .anchor(GBConstraints.NORTHWEST));

        JButton loadButton = new UnfocusableButton("Load ...");
//        loadButton.addActionListener(new f_w(this));
        add(loadButton, new GBConstraints()
                .grid(0, 8)
                .fill(GBConstraints.HORIZONTAL)
                .anchor(GBConstraints.NORTHWEST));
    }

    /**
     * Returns the model displayed in this {@code HeadersTablePanel}.
     *
     * @return the model displayed in this {@code HeadersTablePanel}.
     */
    public HeadersTableModel getModel() {
        return model;
    }
}

/**
 * {@code BooleanCellRenderer} renders booleans using theme-aware {@code JCheckBox}es.
 */
class BooleanCellRenderer extends JCheckBox implements TableCellRenderer {
    /**
     * Returns the {@code JCheckBox} used for drawing the cell.
     *
     * @param table      the {@code JTable} that is asking the renderer to draw; can be {@code null}
     * @param value      the value of the cell to be rendered.  It is up to the specific renderer to interpret and draw
     *                   the value.  For example, if {@code value} is the string "true", it could be rendered as a
     *                   string or as a checkbox that is checked.  {@code null} is a valid value
     * @param isSelected true if the cell is to be rendered with the selection highlighted; otherwise false
     * @param hasFocus   if true, render cell appropriately.  For example, put a special border on the cell, if the cell
     *                   can be edited, render in the color used to indicate editing
     * @param row        the row index of the cell being drawn.  When drawing the header, the value of {@code row} is
     *                   -1
     * @param column     the column index of the cell being drawn
     * @return the {@code JCheckBox} used for drawing the cell.
     * @see JComponent#isPaintingForPrint()
     */
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // hasFocus ensures checkbox highlighted while being clicked
        // TODO: Doesn't update mid-click when ctrl-clicking on the checkbox
        if (isSelected || hasFocus) {
            setBackground(UIManager.getColor("Burp.selectionBackground"));
            setForeground(UIManager.getColor("Burp.selectionForeground"));
        } else if (row % 2 == 0) {
            setBackground(UIManager.getColor("Table.background"));
        } else {
            setBackground(UIManager.getColor("Table.alternateRowColor"));
        }

        setHorizontalAlignment(HORIZONTAL);
        setOpaque(true);
        setEnabled(table.isEnabled());
        setSelected(value != null && (Boolean) value);
        setBorderPainted(true);
        setBorder(hasFocus ? UIManager.getBorder("Table.focusCellHighlightBorder") : new EmptyBorder(1, 1, 1, 1));
        return this;
    }
}
