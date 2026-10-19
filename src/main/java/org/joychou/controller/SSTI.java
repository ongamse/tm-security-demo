package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.StringWriter;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /**
     * Regex that detects dangerous Velocity directives which could allow
     * code execution or file inclusion. Both {@code #set(} and {@code #{set}(}
     * forms are matched.
     */
    private static final Pattern DANGEROUS_DIRECTIVES = Pattern.compile(
        "#\\{?(?:set|evaluate|define|macro|parse|include|stop)\\b"
    );

    private final VelocityEngine velocityEngine;

    public SSTI() {
        velocityEngine = new VelocityEngine();
        // SecureUberspector blocks reflection-based access (getClass, forName,
        // ClassLoader, Runtime, Thread, etc.) preventing RCE via template
        // introspection even if a directive slips through.
        velocityEngine.setProperty(RuntimeConstants.UBERSPECT_CLASSNAME,
            "org.apache.velocity.util.introspection.SecureUberspector");
        velocityEngine.init();
    }

    /**
     * Velocity template evaluation endpoint.
     * Secured against SSTI by:
     * 1. Rejecting templates that contain dangerous directives.
     * 2. Using SecureUberspector to block reflection-based code execution.
     *
     * @param template a Velocity template string (variable interpolation only)
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        if (template == null || DANGEROUS_DIRECTIVES.matcher(template).find()) {
            return;
        }

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        velocityEngine.evaluate(context, swOut, "test", template);
    }
}
