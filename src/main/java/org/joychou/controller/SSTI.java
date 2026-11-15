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

    /** Template source is fixed in code; request data is passed only via the context. */
    private static final String FIXED_TEMPLATE =
            "Author: $author, Address: $address, Phone: $phone, Input: $userInput";

    /**
     * Renders a fixed Velocity template. The user-supplied value is HTML-escaped
     * and passed as context data only, so it is never evaluated as a template.
     *
     * @param template user-provided value (treated as data, not as a template)
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is only ever data in the context, never template source.
        context.put("userInput", template == null ? "" : HtmlUtils.htmlEscape(template));

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
