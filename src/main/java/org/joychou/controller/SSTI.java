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

    // Allowlist of safe, predefined templates keyed by name
    private static final Map<String, String> ALLOWED_TEMPLATES;
    static {
        Map<String, String> m = new HashMap<>();
        m.put("author", "Author: $author");
        m.put("address", "Address: $address");
        m.put("phone", "Phone: $phone");
        m.put("all", "Author: $author, Address: $address, Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(m);
    }

    /**
     * Velocity template rendering with allowlisted template names.
     * The template parameter selects a predefined template by name
     * instead of accepting arbitrary template content.
     *
     * @param template the name of a predefined template (author, address, phone, all)
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        // Validate template name against the allowlist to prevent SSTI
        String safeTemplate = ALLOWED_TEMPLATES.get(template);
        if (safeTemplate == null) {
            throw new IllegalArgumentException("Unknown template name: only 'author', 'address', 'phone', and 'all' are allowed.");
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", safeTemplate);
    }
}
