package org.joychou.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Jdbc Attack @2023.04
 * <p>
 * The endpoints used to open a JDBC connection to a caller supplied (base64 encoded) url, which is a
 * server side request forgery primitive and, through driver properties, a code execution primitive.
 * No JDBC url is accepted from the request any more and no connection is opened; a server side
 * profile map with constant urls would have to be configured before re-enabling them.
 */
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final String DISABLED = "Disabled: connecting to caller supplied jdbc urls is not allowed.";

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public String postgresql() {
        return DISABLED;
    }

    @RequestMapping("/db2")
    public String db2() {
        return DISABLED;
    }
}
