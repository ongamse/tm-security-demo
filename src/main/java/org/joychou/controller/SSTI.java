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

    private static final String FIXED_TEMPLATE = "$author $address $phone $input";

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fix method: the template source is a fixed constant; user input is only
     * passed as a context variable, so it is never parsed as Velocity code.
     *
     * @param template user supplied text, treated purely as data
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        context.put("input", template == null ? "" : template);

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
