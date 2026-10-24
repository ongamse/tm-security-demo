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
     * Velocity template rendering. User input is passed as context data,
     * not as template code, to prevent Server-Side Template Injection (SSTI).
     *
     * @param template user-supplied text rendered as data within a fixed template
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is placed into context as data, never evaluated as template code
        context.put("userInput", template != null ? template : "");

        // Fixed template controlled by the developer; user input is only referenced as a variable
        String safeTemplate = "Author: $author\nAddress: $address\nPhone: $phone\nInput: $userInput";

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", safeTemplate);
        return swOut.toString();
    }
}
