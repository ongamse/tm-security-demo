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

    /**
     * Predefined, safe Velocity templates keyed by name.
     * User input selects a template by name from this allowlist;
     * arbitrary template code from user input is never evaluated.
     */
    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> map = new HashMap<>();
        map.put("default", "Author: $author, Address: $address, Phone: $phone");
        map.put("author_only", "Author: $author");
        map.put("contact", "Address: $address, Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(map);
    }

    /**
     * Velocity template rendering using an allowlist of predefined template names.
     * User input selects a template by name; it is never used as template content.
     *
     * @param template the name of a predefined template (e.g. "default", "author_only", "contact")
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        if (template == null || !template.matches("^[a-zA-Z_]+$")) {
            return "Invalid template name.";
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        // Allowlist: only evaluate predefined templates, never user-supplied content
        String templateContent = ALLOWED_TEMPLATES.get(template);
        if (templateContent == null) {
            return "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet();
        }

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateContent);
        return swOut.toString();
    }
}
