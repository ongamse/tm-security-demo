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

    /** Fixed, repo-controlled template. Never build this from request data. */
    private static final String FIXED_TEMPLATE =
            "Author: $author, Address: $address, Phone: $phone, Input: $input";

    /**
     * Velocity rendering with a fixed template. The user-supplied value is passed only
     * as an HTML-escaped context variable and is never evaluated as a template.
     *
     * @param template user input, treated as data only
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        // User input is only exposed as an HTML-escaped context variable; it is never
        // used as the Velocity template source.
        context.put("input", template == null ? "" : HtmlUtils.htmlEscape(template));

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
