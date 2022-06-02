package dev.jkmartindale.customheaders.model;

/**
 * {@code CustomHeader} represents a header to be added to requests in a Burp Suite session handling rule.
 */
public class CustomHeader {
    /**
     * Name of the header
     */
    private final String name;
    /**
     * Prefix before the header value
     */
    private final String prefix;
    /**
     * Value of the header (without prefix)
     */
    private final String value;
    /**
     * Whether the rule is enabled
     */
    private boolean enabled;

    /**
     * Construct a new header rule by specifying all properties.
     *
     * @param enabled whether the rule is enabled
     * @param name    name of the header
     * @param prefix  prefix before the header value
     * @param value   value of the header (without prefix)
     */
    public CustomHeader(boolean enabled, String name, String prefix, String value) {
        this.enabled = enabled;
        this.name = name.strip();
        this.prefix = prefix != null ? prefix.strip() : "";
        this.value = value.strip();
    }

    /**
     * Returns whether this {@code CustomHeader} is available to be added to requests.
     *
     * @return true if enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Set whether this {@code CustomHeader} should be added to requests.
     *
     * @param enabled true to enable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Returns the name of the header.
     *
     * @return part of the header before the colon
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the prefix applied to header values.
     *
     * @return header value prefix, or empty string if none
     */
    public String getPrefix() {
        return prefix;
    }

    /**
     * Returns the header value.
     *
     * @return part of the header after the colon
     */
    public String getValue() {
        return value;
    }

    /**
     * Returns a string representation of the object. In general, the {@code toString} method returns a string that
     * "textually represents" this object. The result should be a concise but informative representation that is easy
     * for a person to read. It is recommended that all subclasses override this method.
     * <p>
     * The {@code toString} method for class {@code Object} returns a string consisting of the name of the class of
     * which the object is an instance, the at-sign character `{@code @}', and the unsigned hexadecimal representation
     * of the hash code of the object. In other words, this method returns a string equal to the value of:
     * <blockquote>
     * <pre>
     * getClass().getName() + '@' + Integer.toHexString(hashCode())
     * </pre></blockquote>
     *
     * @return a string representation of the object.
     */
    @Override
    public String toString() {
        String value = prefix.length() != 0 ? prefix + " " + this.value : this.value;
        return name + ": " + value;
    }
}
