package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /**
     * Velocity template rendering endpoint.
     * User input is placed in the context as data, not used as template code,
     * to prevent Server-Side Template Injection (SSTI).
     *
     * @param template user-supplied text rendered as data
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is placed into the context as a data value, not as template code.
        // Velocity context values are rendered as plain strings and are NOT
        // re-evaluated as template directives, preventing SSTI.
        context.put("userInput", template);

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", "$userInput");
    }
}
