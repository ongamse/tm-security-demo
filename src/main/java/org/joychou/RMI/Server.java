package org.joychou.RMI;


public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {
        // The RMI registry listener (port 1099) and the remote binding were removed: an exposed
        // registry accepts serialized objects from the network and cannot be made safe by filtering.
        System.out.println("RMI registry is disabled; no remote object is exported.");
    }
}
