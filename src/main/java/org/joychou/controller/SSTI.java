package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    private static final Map<String, String> ALLOWED_TEMPLATES = new HashMap<>();

    static {
        ALLOWED_TEMPLATES.put("contact", "Author: $author, Address: $address, Phone: $phone");
        ALLOWED_TEMPLATES.put("author", "Author: $author");
        ALLOWED_TEMPLATES.put("address", "Address: $address");
        ALLOWED_TEMPLATES.put("phone", "Phone: $phone");
    }

    /**
     * Velocity template rendering using an allowlist of predefined template names.
     * User input selects a template by name; raw user content is never evaluated.
     *
     * @param template the name of a predefined template to render
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        if (template == null || !ALLOWED_TEMPLATES.containsKey(template)) {
            return "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet();
        }

        String templateContent = ALLOWED_TEMPLATES.get(template);

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateContent);
        return swOut.toString();
    }
}
