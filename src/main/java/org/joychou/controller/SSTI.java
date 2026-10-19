package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    // Allowlist of safe, predefined template strings keyed by name.
    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("default", "Author: $author, Address: $address, Phone: $phone");
        m.put("author_only", "Author: $author");
        m.put("contact", "Address: $address, Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(m);
    }

    /**
     * Renders a Velocity template selected by name from a predefined allowlist.
     * Arbitrary user-supplied template strings are rejected to prevent SSTI.
     *
     * @param template the allowlisted template name (e.g. "default", "author_only", "contact")
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        String templateContent = ALLOWED_TEMPLATES.get(template);
        if (templateContent == null) {
            return "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet();
        }

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateContent);
        return swOut.toString();
    }
}
