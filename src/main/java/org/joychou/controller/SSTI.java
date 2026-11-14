package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /** Fixed template source; request data must never be concatenated into it. */
    private static final String FIXED_TEMPLATE = "$author, $address, $phone: $input";

    /**
     * Velocity rendering with a fixed template. The request parameter is bound
     * as an HTML-escaped context variable and is never evaluated as template source.
     *
     * @param template user-supplied text (treated as data only)
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // Request data is only ever bound as an escaped context variable; it is never template source.
        context.put("input", template == null ? "" : HtmlUtils.htmlEscape(template));

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
