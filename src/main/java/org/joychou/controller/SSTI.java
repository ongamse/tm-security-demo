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
     * User input is passed as data into a fixed template, not evaluated as a template itself.
     *
     * @param template user-supplied text rendered safely as data
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is passed as a context variable, never evaluated as a template
        context.put("userInput", template);

        // Fixed template that safely references the user-supplied data
        String safeTemplate = "Author: $author, Address: $address, Phone: $phone, Input: $userInput";

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", safeTemplate);
        return swOut.toString();
    }
}
