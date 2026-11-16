package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.http.ResponseEntity;
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

    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> templates = new HashMap<>();
        templates.put("author", "Author: $author");
        templates.put("address", "Address: $address");
        templates.put("phone", "Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(templates);
    }

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fix method: user input is only a template name that is looked up in a fixed
     * allowlist of server-side template sources; user-supplied template source is
     * never passed to Velocity.evaluate.
     * <p>
     * http://localhost:8080/ssti/velocity?template=author
     *
     * @param template name of an allowlisted template
     */
    @GetMapping("/velocity")
    public ResponseEntity<String> velocity(String template) {
        String templateSource = template == null ? null : ALLOWED_TEMPLATES.get(template);
        if (templateSource == null) {
            return ResponseEntity.badRequest().body("Unknown template");
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateSource);
        return ResponseEntity.ok().build();
    }
}
