package org.joychou.controller;

import java.util.HashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/claims")
public class ClaimController {

    private static final Map<Long, Map<String, Object>> CLAIMS = new HashMap<Long, Map<String, Object>>();

    static {
        CLAIMS.put(1L, claim(1L, "alice", "Water damage, policy 1001"));
        CLAIMS.put(2L, claim(2L, "bob", "Auto collision, policy 2002"));
    }

    private static Map<String, Object> claim(Long id, String owner, String detail) {
        Map<String, Object> c = new HashMap<String, Object>();
        c.put("id", id);
        c.put("owner", owner);
        c.put("detail", detail);
        return c;
    }

    /**
     * Fixed: only the owner can read a claim.
     */
    @GetMapping("/{id}")
    public org.springframework.http.ResponseEntity<Map<String, Object>> get(@PathVariable Long id, java.security.Principal caller) {
        Map<String, Object> c = CLAIMS.get(id);
        if (c == null || caller == null || !caller.getName().equals(c.get("owner"))) {
            return org.springframework.http.ResponseEntity.notFound().build();
        }
        return org.springframework.http.ResponseEntity.ok(c);
    }
}
