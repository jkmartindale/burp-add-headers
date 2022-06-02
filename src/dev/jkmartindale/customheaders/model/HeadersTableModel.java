package dev.jkmartindale.customheaders.model;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * {@code HeadersTableModel} manages the model used by {@code HeadersTablePanel} to display header addition rules.
 */
public class HeadersTableModel extends AbstractTableModel {
    /**
     * Columns to display in the table.
     */
    private static final Column[] columns = {
            new Column("Enabled", Boolean.class, 15),
            new Column("Name", String.class, 40),
            new Column("Value Prefix", String.class, 20),
            new Column("Value", String.class, 40)
    };

    // TODO: not this
    private final ArrayList<CustomHeader> headers = new ArrayList<>(Arrays.asList(
            new CustomHeader(true, "Authorization", "Bearer", "lol idk"),
            new CustomHeader(false, "user-Agent", "", "Joe"),
            new CustomHeader(true, "upgrade-insecure-requests", "", "1"),
            new CustomHeader(false, "Zedd", "", "is epic")
    ));

    /**
     * Adds a new header to this model.
     *
     * @param header header to add
     */
    public void addHeader(CustomHeader header) {
        headers.add(header);
        int index = headers.size() - 1;
        fireTableRowsInserted(index, index);
    }

    /**
     * Gets a header by model row index.
     *
     * @param index model row index (not necessarily view index)
     * @return header located at the model index
     * @see JTable#convertRowIndexToModel(int)
     */
    public CustomHeader getHeader(int index) {
        return headers.get(index);
    }

    /**
     * Removes headers by model row indices.
     *
     * @param rows model row indices (not necessarily view indices)
     * @see JTable#convertRowIndexToModel(int)
     */
    public void removeHeaders(int[] rows) {
        for (int row : rows) {
            headers.remove(row);
            // Inefficient I guess, but too lazy to detect continuous selections inside selection list
            fireTableRowsDeleted(row, row);
        }
    }

    /**
     * Replaces a header at a given model row index.
     *
     * @param index  model row index (not necessarily view index)
     * @param header new header to replace the old data
     * @see JTable#convertRowIndexToModel(int)
     */
    public void setHeader(int index, CustomHeader header) {
        headers.set(index, header);
        fireTableRowsUpdated(index, index);
    }

    /**
     * Sets the preferred column widths of a table based on the columns in this model.
     *
     * @param table preferably a {@code JTable} with this table model
     */
    public void updateColumnWidths(JTable table) {
        int widthScale = Math.max(table.getFontMetrics(table.getFont()).charWidth('X'), 6);
        TableColumnModel columnModel = table.getColumnModel();
        int columnCount = Math.min(columnModel.getColumnCount(), columns.length);
        for (int i = 0; i < columnCount; i++) {
            columnModel.getColumn(i).setPreferredWidth(widthScale * columns[i].width);
        }
    }

    /**
     * Returns the value for the cell at {@code columnIndex} and {@code rowIndex}.
     *
     * @param rowIndex    the row whose value is to be queried
     * @param columnIndex the column whose value is to be queried
     * @return the value Object at the specified cell, or null if not found
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex > getRowCount() || rowIndex < 0) {
            return null;
        }

        CustomHeader header = headers.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return header.isEnabled();
            case 1:
                return header.getName();
            case 2:
                return header.getPrefix();
            case 3:
                return header.getValue();
        }

        return null;
    }

    /**
     * Returns true for the "Enabled" column and false otherwise.
     *
     * @param rowIndex    the row being queried
     * @param columnIndex the column being queried
     * @return true if the cell is editable
     */
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0;
    }

    /**
     * Sets the value in the cell at {@code columnIndex} and {@code rowIndex} to {@code aValue}. Only works for header
     * enable/disable checkboxes.
     *
     * @param aValue      the new value
     * @param rowIndex    the row whose value is to be changed
     * @param columnIndex the column whose value is to be changed
     * @see #getValueAt
     * @see #isCellEditable
     */
    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex > getRowCount() || columnIndex < 0 || columnIndex > 1) {
            return;
        }
        headers.get(rowIndex).setEnabled((Boolean) aValue);
    }

    /**
     * Returns the most specific superclass for all the cell values in the column. If {@code columnIndex} doesn't
     * correspond to an existing column, {@code Object.class} is returned. This is used by the {@code JTable} to set up
     * a default renderer and editor for the column.
     *
     * @param columnIndex the column being queried
     * @return the class for values in the column, or {@code Object.class} if not found
     */
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex < 0 || columnIndex > columns.length) {
            return Object.class;
        }
        return columns[columnIndex].dataClass;
    }

    /**
     * Returns the number of columns in the model. A {@code JTable} uses this method to determine how many columns it
     * should create and display by default.
     *
     * @return the number of columns in the model
     * @see #getRowCount
     */
    @Override
    public int getColumnCount() {
        return columns.length;
    }

    /**
     * Returns the name of the column at {@code columnIndex}. This is used to initialize the table's column header
     * name.
     *
     * @param column the column being queried
     * @return a string containing the name of {@code column}, or empty string if not found
     */
    @Override
    public String getColumnName(int column) {
        if (column < 0 || column > columns.length) {
            return "";
        }
        return columns[column].name;
    }

    /**
     * Returns the number of rows in the model. A {@code JTable} uses this method to determine how many rows it should
     * display.
     *
     * @return the number of rows in the model
     * @see #getColumnCount
     */
    @Override
    public int getRowCount() {
        return headers.size();
    }

    /**
     * Returns a sequential {@code Stream} of header creation rules.
     *
     * @return a sequential {@code Stream} of header creation rules
     */
    public Stream<CustomHeader> stream() {
        return headers.stream();
    }
}
