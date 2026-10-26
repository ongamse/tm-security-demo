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
     * User input is passed as a context variable, not as template source,
     * to prevent Server-Side Template Injection (SSTI).
     *
     * @param template user-supplied text rendered safely as a variable
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is placed into the context as data, never evaluated as template code.
        context.put("userInput", template);

        // Static template references the user input safely through a variable.
        String safeTemplate = "$userInput";

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", safeTemplate);
        return swOut.toString();
    }
}
