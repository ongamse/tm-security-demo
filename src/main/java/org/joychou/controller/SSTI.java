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

    private static final String FIXED_TEMPLATE =
            "author: $author, address: $address, phone: $phone, input: $input";

    /**
     * Velocity rendering with a fixed template. The user supplied value is never
     * evaluated as template source; it is only passed (HTML-escaped) as a context variable.
     *
     * @param template user supplied text, rendered as plain escaped data
     * @return the rendered, HTML-escaped output
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        context.put("input", template == null ? "" : HtmlUtils.htmlEscape(template));

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
        return swOut.toString();
    }
}
