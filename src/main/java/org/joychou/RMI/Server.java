package org.joychou.RMI;


/**
 * Demo implementation of {@link Hello}. It is intentionally not exported: no RMI registry is
 * created and no remote object is bound, so there is no network-reachable RMI endpoint.
 */
public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String[] args) {
        System.out.println("RMI server start-up is disabled.");
    }
}
