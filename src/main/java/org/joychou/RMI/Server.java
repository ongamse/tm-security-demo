package org.joychou.RMI;


/**
 * Hello implementation kept for API compatibility. It intentionally does not start an RMI
 * registry or export remote objects, so the application opens no RMI network listener.
 */
public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String[] args) {
        System.err.println("RMI registry startup is disabled; no remote objects are exported.");
    }
}
