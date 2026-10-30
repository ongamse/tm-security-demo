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

    // Allowlist of safe, predefined Velocity templates keyed by name.
    private static final Map<String, String> ALLOWED_TEMPLATES;
    static {
        Map<String, String> templates = new HashMap<>();
        templates.put("greeting", "Hello $author from $address. Phone: $phone");
        templates.put("contact", "Contact: $author, $address, $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(templates);
    }

    /**
     * Velocity template rendering using an allowlist of template names.
     * The user-supplied parameter selects a predefined template by name
     * rather than being evaluated as raw template content.
     *
     * @param template the name of a predefined template to render
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        String templateContent = ALLOWED_TEMPLATES.get(template);
        if (templateContent == null) {
            return "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet();
        }

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateContent);
        return swOut.toString();
    }
}
