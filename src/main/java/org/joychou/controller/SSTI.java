package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /**
     * Maps the request value to a server-side constant template source.
     * The request string itself is never used as a template or a lookup key
     * into a collection.
     *
     * @return a literal template source, or null if the name is not known
     */
    private static String templateSourceFor(String name) {
        if (name == null) {
            return null;
        }
        switch (name) {
            case "author":
                return "Author: $author";
            case "address":
                return "Address: $address";
            case "phone":
                return "Phone: $phone";
            default:
                return null;
        }
    }

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fix method: user input is only a template name that is mapped to a fixed
     * server-side template source; user-supplied template source is
     * never passed to Velocity.evaluate.
     * <p>
     * http://localhost:8080/ssti/velocity?template=author
     *
     * @param template name of an allowlisted template
     */
    @GetMapping("/velocity")
    public ResponseEntity<String> velocity(String template) {
        String templateSource = templateSourceFor(template);
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
