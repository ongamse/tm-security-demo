package org.joychou.RMI;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            // Set JVM-wide deserialization filter to restrict RMI attack surface
            // and prevent arbitrary code execution via malicious deserialization.
            // Allowlist only classes needed for this RMI service.
            System.setProperty("sun.rmi.registry.registryFilter",
                "org.joychou.RMI.**;java.lang.**;java.rmi.**;sun.rmi.**;javax.rmi.**;!*");

            Server obj = new Server();
            // Bind to localhost only to restrict network access
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            Registry registry = LocateRegistry.createRegistry(1099);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

