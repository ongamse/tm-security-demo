package org.joychou.RMI;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        // The RMI registry/server is intentionally not started: it would expose a network-reachable
        // deserialization endpoint. The class is kept so Hello/Client still compile.
        System.out.println("RMI server start is disabled.");
    }
}

