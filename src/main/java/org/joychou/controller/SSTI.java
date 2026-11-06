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

    private static final String FIXED_TEMPLATE =
            "Author: $author, Address: $address, Phone: $phone, Input: $userInput";

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fixed: the template source is a constant; the request parameter is passed
     * only as a bound context variable and is never evaluated as a template.
     *
     * @param template user input (bound as $userInput)
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is only a bound context value; it is never parsed as template source.
        context.put("userInput", template);

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
