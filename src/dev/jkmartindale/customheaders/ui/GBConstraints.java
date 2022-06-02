package dev.jkmartindale.customheaders.ui;

import java.awt.*;

/**
 * {@code GBConstraints} is a subclassed {@code GridBagConstraints} supporting the builder model for saner use. Inspired
 * by <a href="https://stackoverflow.com/a/21030105/3427178">https://stackoverflow.com/a/21030105/3427178</a>.
 */
public class GBConstraints extends GridBagConstraints {
    /**
     * This field is used when the component is smaller than its display area. It determines where, within the display
     * area, to place the component.
     * <p> There are three kinds of possible values: orientation
     * relative, baseline relative and absolute.  Orientation relative values are interpreted relative to the
     * container's component orientation property, baseline relative values are interpreted relative to the baseline and
     * absolute values are not.  The absolute values are: {@code CENTER}, {@code NORTH}, {@code NORTHEAST}, {@code
     * EAST}, {@code SOUTHEAST}, {@code SOUTH}, {@code SOUTHWEST}, {@code WEST}, and {@code NORTHWEST}. The orientation
     * relative values are: {@code PAGE_START}, {@code PAGE_END}, {@code LINE_START}, {@code LINE_END}, {@code
     * FIRST_LINE_START}, {@code FIRST_LINE_END}, {@code LAST_LINE_START} and {@code LAST_LINE_END}.  The baseline
     * relative values are: {@code BASELINE}, {@code BASELINE_LEADING}, {@code BASELINE_TRAILING}, {@code
     * ABOVE_BASELINE}, {@code ABOVE_BASELINE_LEADING}, {@code ABOVE_BASELINE_TRAILING}, {@code BELOW_BASELINE}, {@code
     * BELOW_BASELINE_LEADING}, and {@code BELOW_BASELINE_TRAILING}. The default value is {@code CENTER}.
     *
     * @serial
     * @see #clone()
     * @see java.awt.ComponentOrientation
     */
    public GBConstraints anchor(int anchor) {
        this.anchor = anchor;
        return this;
    }

    /**
     * This field is used when the component's display area is larger than the component's requested size. It determines
     * whether to resize the component, and if so, how.
     * <p>
     * The following values are valid for {@code fill}:
     *
     * <ul>
     * <li>
     * {@code NONE}: Do not resize the component.
     * <li>
     * {@code HORIZONTAL}: Make the component wide enough to fill
     *         its display area horizontally, but do not change its height.
     * <li>
     * {@code VERTICAL}: Make the component tall enough to fill its
     *         display area vertically, but do not change its width.
     * <li>
     * {@code BOTH}: Make the component fill its display area
     *         entirely.
     * </ul>
     * <p>
     * The default value is {@code NONE}.
     *
     * @serial
     * @see #clone()
     */
    public GBConstraints fill(int fill) {
        this.fill = fill;
        return this;
    }

    /**
     * Specifies the cell containing the leading edge  and top of the component's display area, where the first cell in
     * a row has {@code gridx=0} and the topmost cell has {@code gridy=0}. The leading edge of a component's display
     * area is its left edge for a horizontal, left-to-right container and its right edge for a horizontal,
     * right-to-left container. The value {@code RELATIVE} specifies that the component be placed immediately following
     * ({@code gridx}) or just below ({@code gridy}) the component that was added to the container just before this
     * component was added.
     * <p>
     * The default value is {@code RELATIVE}. {@code gridx}/{@code gridy} should be non-negative values.
     *
     * @serial
     * @see #clone()
     * @see java.awt.GridBagConstraints#gridx
     * @see java.awt.GridBagConstraints#gridy
     * @see java.awt.ComponentOrientation
     */
    public GBConstraints grid(int gridx, int gridy) {
        this.gridx = gridx;
        this.gridy = gridy;
        return this;
    }

    /**
     * Specifies the number of cells in a row and column for the component's display area.
     * <p>
     * Use {@code REMAINDER} to specify that the component's display area will be from {@code gridx}/{@code gridy} to
     * the last cell in the column. Use {@code RELATIVE} to specify that the component's display area will be from
     * {@code gridx}/{@code gridy} to the next to the last one in its column.
     * <p>
     * {@code gridheight} and {@code gridheight} should be non-negative values and the default values are 1.
     *
     * @serial
     * @see #clone()
     * @see java.awt.GridBagConstraints#gridwidth
     * @see java.awt.GridBagConstraints#gridheight
     */
    public GBConstraints gridspan(int gridwidth, int gridheight) {
        this.gridwidth = gridwidth;
        this.gridheight = gridheight;
        return this;
    }

    /**
     * Specifies the number of cells in a column for the component's display area.
     * <p>
     * Use {@code REMAINDER} to specify that the component's display area will be from {@code gridy} to the last cell in
     * the column. Use {@code RELATIVE} to specify that the component's display area will be from {@code gridy} to the
     * next to the last one in its column.
     * <p>
     * {@code gridheight} should be a non-negative value and the default value is 1.
     *
     * @serial
     * @see #clone()
     * @see java.awt.GridBagConstraints#gridwidth
     */
    public GBConstraints gridheight(int gridheight) {
        this.gridheight = gridheight;
        return this;
    }

    /**
     * Specifies the number of cells in a row for the component's display area.
     * <p>
     * Use {@code REMAINDER} to specify that the component's display area will be from {@code gridx} to the last cell in
     * the row. Use {@code RELATIVE} to specify that the component's display area will be from {@code gridx} to the next
     * to the last one in its row.
     * <p>
     * {@code gridwidth} should be non-negative and the default value is 1.
     *
     * @serial
     * @see #clone()
     * @see java.awt.GridBagConstraints#gridheight
     */
    public GBConstraints gridwidth(int gridwidth) {
        this.gridwidth = gridwidth;
        return this;
    }

    /**
     * Specifies the cell containing the leading edge of the component's display area, where the first cell in a row has
     * {@code gridx=0}. The leading edge of a component's display area is its left edge for a horizontal, left-to-right
     * container and its right edge for a horizontal, right-to-left container. The value {@code RELATIVE} specifies that
     * the component be placed immediately following the component that was added to the container just before this
     * component was added.
     * <p>
     * The default value is {@code RELATIVE}. {@code gridx} should be a non-negative value.
     *
     * @serial
     * @see #clone()
     * @see #grid
     * @see java.awt.GridBagConstraints#gridy
     * @see java.awt.ComponentOrientation
     */
    public GBConstraints gridx(int gridx) {
        this.gridx = gridx;
        return this;
    }

    /**
     * Specifies the cell at the top of the component's display area, where the topmost cell has {@code gridy=0}. The
     * value {@code RELATIVE} specifies that the component be placed just below the component that was added to the
     * container just before this component was added.
     * <p>
     * The default value is {@code RELATIVE}. {@code gridy} should be a non-negative value.
     *
     * @serial
     * @see #clone()
     * @see #grid
     * @see java.awt.GridBagConstraints#gridx
     */
    public GBConstraints gridy(int gridy) {
        this.gridy = gridy;
        return this;
    }

    /**
     * This field specifies the external padding of the component, the minimum amount of space between the component and
     * the edges of its display area. Unlike the {@code GridBagConstraints} property, this assumes you don't want to
     * create an {@code Insets} object yourself.
     * <p>
     * The default value is 0 for all four properties.
     *
     * @serial
     * @see #clone()
     */
    public GBConstraints insets(int top, int left, int bottom, int right) {
        this.insets = new Insets(top, left, bottom, right);
        return this;
    }

    /**
     * Specifies the internal padding of the component, which is how much space to add to the minimum width of the
     * component. The width of the component is at least its minimum width plus {@code ipadx} pixels and the height is
     * at least its minimum height plus {@code ipady} pixels.
     *
     * @param ipadx
     * @param ipady
     * @see #clone()
     * @see java.awt.GridBagConstraints#ipadx
     * @see java.awt.GridBagConstraints#ipady
     */
    public GBConstraints ipad(int ipadx, int ipady) {
        this.ipadx = ipadx;
        this.ipady = ipady;
        return this;
    }

    /**
     * This field specifies the internal padding of the component, that is, how much space to add to the minimum width
     * of the component. The width of the component is at least its minimum width plus {@code ipadx} pixels.
     * <p>
     * The default value is {@code 0}.
     *
     * @serial
     * @see #clone()
     * @see #ipad
     * @see java.awt.GridBagConstraints#ipady
     */
    public GBConstraints ipadx(int ipadx) {
        this.ipadx = ipadx;
        return this;
    }

    /**
     * This field specifies the internal padding of the component, that is, how much space to add to the minimum height
     * of the component. The height of the component is at least its minimum height plus {@code ipady} pixels.
     * <p>
     * The default value is 0.
     *
     * @serial
     * @see #clone()
     * @see #ipad
     * @see java.awt.GridBagConstraints#ipadx
     */
    public GBConstraints ipady(int ipady) {
        this.ipady = ipady;
        return this;
    }

    /**
     * Specifies how to distribute extra horizontal/vertical space.
     * <p>
     * The grid bag layout manager calculates the weight of a column/row to be the maximum {@code weightx}/{@code
     * weighty} of all the components in a column/row. If the resulting layout is smaller horizontally/vertically than
     * the area it needs to fill, the extra space is distributed to each column/row in proportion to its weight. A
     * column/row that has a weight of zero receives no extra space.
     * <p>
     * If all the weights are zero, all the extra space appears between the grids of the cell and the left/right or
     * top/bottom edges.
     * <p>
     * The default value is {@code 0}. {@code weightx}/{@code weighty} should be non-negative values.
     *
     * @serial
     * @see #clone()
     * @see java.awt.GridBagConstraints#weightx
     * @see java.awt.GridBagConstraints#weighty
     */
    public GBConstraints weight(double weightx, double weighty) {
        this.weightx = weightx;
        this.weighty = weighty;
        return this;
    }

    /**
     * Specifies how to distribute extra horizontal space.
     * <p>
     * The grid bag layout manager calculates the weight of a column to be the maximum {@code weightx} of all the
     * components in a column. If the resulting layout is smaller horizontally than the area it needs to fill, the extra
     * space is distributed to each column in proportion to its weight. A column that has a weight of zero receives no
     * extra space.
     * <p>
     * If all the weights are zero, all the extra space appears between the grids of the cell and the left and right
     * edges.
     * <p>
     * The default value of this field is {@code 0}. {@code weightx} should be a non-negative value.
     *
     * @serial
     * @see #clone()
     * @see #weight
     * @see java.awt.GridBagConstraints#weighty
     */
    public GBConstraints weightx(double weightx) {
        this.weightx = weightx;
        return this;
    }

    /**
     * Specifies how to distribute extra vertical space.
     * <p>
     * The grid bag layout manager calculates the weight of a row to be the maximum {@code weighty} of all the
     * components in a row. If the resulting layout is smaller vertically than the area it needs to fill, the extra
     * space is distributed to each row in proportion to its weight. A row that has a weight of zero receives no extra
     * space.
     * <p>
     * If all the weights are zero, all the extra space appears between the grids of the cell and the top and bottom
     * edges.
     * <p>
     * The default value of this field is {@code 0}. {@code weighty} should be a non-negative value.
     *
     * @serial
     * @see #clone()
     * @see #weight
     * @see java.awt.GridBagConstraints#weightx
     */
    public GBConstraints weighty(double weighty) {
        this.weighty = weighty;
        return this;
    }
}
