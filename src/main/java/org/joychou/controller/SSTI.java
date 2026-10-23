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
     * User input is passed as a context variable, never evaluated as template code.
     *
     * @param template user-supplied value rendered safely as data
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is placed in the context as a data value, not interpreted as template code.
        context.put("userInput", template);

        // Fixed template string — user data is rendered via $userInput, preventing SSTI.
        String safeTemplate = "Author: $author, Address: $address, Phone: $phone, Input: $userInput";

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", safeTemplate);
    }
}
