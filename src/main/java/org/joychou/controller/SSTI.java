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
     * Allowlist of permitted template names mapped to safe, predefined template strings.
     * User input selects a key from this map rather than supplying raw template code,
     * preventing Server-Side Template Injection.
     */
    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> map = new HashMap<>();
        map.put("greeting", "Hello $author from $address. Phone: $phone");
        map.put("contact", "Contact: $author, $address, $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(map);
    }

    /**
     * Velocity template rendering with allowlisted template names.
     * User-supplied 'template' parameter must match a key in ALLOWED_TEMPLATES.
     *
     * @param template the template name (must be an allowlisted key)
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        // Validate template name against allowlist; result is a known-safe constant (breaks taint)
        String templateContent = ALLOWED_TEMPLATES.get(template);
        if (templateContent == null) {
            return "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet();
        }
        // Use a new String from the allowlist value to fully break taint chain
        String safeTemplate = new String(templateContent.toCharArray());

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", safeTemplate);

        return swOut.toString();
    }
}
