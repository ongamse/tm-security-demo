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

    // Allowlist of pre-defined, safe template content keyed by template name.
    // User input selects a name from this map; arbitrary template content is never evaluated.
    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("default", "Author: $author, Address: $address, Phone: $phone");
        m.put("author_only", "Author: $author");
        m.put("contact", "Address: $address, Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(m);
    }

    /**
     * Velocity template rendering with allowlisted template names only.
     * User input selects a pre-defined template by name; direct template
     * content from user input is rejected to prevent SSTI / RCE.
     *
     * @param template the name of an allowed template (e.g. "default", "author_only", "contact")
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        // Validate that the requested template name is in the allowlist
        String safeTemplate = ALLOWED_TEMPLATES.get(template);
        if (safeTemplate == null) {
            return "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet();
        }

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", safeTemplate);
        return swOut.toString();
    }
}
