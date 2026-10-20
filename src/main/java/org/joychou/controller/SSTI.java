package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /** Allowlist of safe, predefined Velocity templates keyed by name. */
    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("default", "Author: $author, Address: $address, Phone: $phone");
        m.put("author", "Author: $author");
        m.put("contact", "Address: $address, Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(m);
    }

    /**
     * Velocity template rendering endpoint.
     * Only predefined template names from the allowlist are accepted.
     *
     * @param template the name of an allowed template (e.g. "default", "author", "contact")
     * @return rendered template output
     */
    @GetMapping("/velocity")
    public String velocity(@RequestParam(defaultValue = "default") String template) {
        String templateContent = ALLOWED_TEMPLATES.get(template);
        if (templateContent == null) {
            return "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet();
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateContent);
        return swOut.toString();
    }
}
