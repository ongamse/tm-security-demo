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

    // Allowlist of permitted template names mapped to safe, fixed template strings.
    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> map = new HashMap<>();
        map.put("default", "Author: $author, Address: $address, Phone: $phone");
        map.put("author", "Author: $author");
        map.put("contact", "Address: $address, Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(map);
    }

    /**
     * Velocity template rendering endpoint.
     * Only allowlisted template names are accepted; user input is never
     * evaluated as template code.
     *
     * @param template the name of an allowlisted template (default, author, contact)
     */
    @GetMapping("/velocity")
    public String velocity(@RequestParam(defaultValue = "default") String template) {
        String templateBody = ALLOWED_TEMPLATES.get(template);
        if (templateBody == null) {
            return "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet();
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateBody);
        return swOut.toString();
    }
}
