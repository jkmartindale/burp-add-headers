package burp;

import dev.jkmartindale.customheaders.model.CustomHeader;
import dev.jkmartindale.customheaders.model.HeadersTableModel;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Burp session handling rule to add headers to eligible requests.
 */
public class AddHeaderSessionAction implements ISessionHandlingAction {
    /**
     * Static instance of Burp extension helpers.
     */
    static final IExtensionHelpers helpers = BurpExtender.getCallbacks().getHelpers();
    /**
     * Name displayed in session handling rule editor.
     */
    private final String name;
    /**
     * Header rules data.
     */
    private final HeadersTableModel model;

    /**
     * Creates a new Burp session handling action called {@code name} that adds enabled headers from {@code model}.
     * @param name name of the session handling action
     * @param model table model containing header rule data
     */
    public AddHeaderSessionAction(String name, HeadersTableModel model) {
        this.name = name;
        this.model = model;
        BurpExtender.getCallbacks().registerSessionHandlingAction(this);
    }

    /**
     * This method is used by Burp to obtain the name of the session handling action. This will be displayed as an
     * option within the session handling rule editor when the user selects to execute an extension-provided action.
     *
     * @return The name of the action.
     */
    @Override
    public String getActionName() {
        return name;
    }

    /**
     * This method is invoked when the session handling action should be executed. This may happen as an action in its
     * own right, or as a sub-action following execution of a macro.
     *
     * @param currentRequest The base request that is currently being processed. The action can query this object to
     *                       obtain details about the base request. It can issue additional requests of its own if
     *                       necessary, and can use the setter methods on this object to update the base request.
     * @param macroItems     If the action is invoked following execution of a macro, this parameter contains the result
     *                       of executing the macro. Otherwise, it is {@code null}. Actions can use the details of the
     *                       macro items to perform custom analysis of the macro to derive values of non-standard
     *                       session handling tokens, etc.
     */
    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        IRequestInfo requestInfo = helpers.analyzeRequest(currentRequest);
        byte[] request = currentRequest.getRequest();

        List<CustomHeader> enabledRules = model.stream()
                .filter(CustomHeader::isEnabled)
                .collect(Collectors.toList());

        // Replace existing headers with the name as new headers to add
        // Best choice for default behavior as you can still dupe headers with extension settings
        Set<String> newHeaderNames = enabledRules.stream()
                .map(header -> header.getName().toLowerCase()) // Headers are case-insensitive
                .collect(Collectors.toSet());
        Stream<String> oldHeaders = requestInfo.getHeaders().stream()
                .filter(header -> !newHeaderNames.contains(header.split(":")[0].toLowerCase()));

        // Merge lists
        List<String> headers = oldHeaders.collect(Collectors.toList());
        headers.addAll(enabledRules.stream()
                .map(CustomHeader::toString)
                .collect(Collectors.toList())
        );

        currentRequest.setRequest(helpers.buildHttpMessage(
                headers,
                Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length)
        ));
    }
}
