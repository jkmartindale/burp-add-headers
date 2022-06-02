package dev.jkmartindale.customheaders.model;

/**
 * {@code Column} represents useful metadata about a table column. This class is used to enable DRY for {@code
 * HeadersTableModel}'s {@code TableModel} interface implementation.
 */
public class Column {
    public String name;
    public Class dataClass;
    public int width;

    /**
     * Creates a new Column by defining all of its properties.
     *
     * @param name      name of the column
     * @param dataClass common class of the column cells
     * @param width     base width for the column's preferredWidth()
     */
    public Column(String name, Class dataClass, int width) {
        this.name = name;
        this.dataClass = dataClass;
        this.width = width;
    }
}
