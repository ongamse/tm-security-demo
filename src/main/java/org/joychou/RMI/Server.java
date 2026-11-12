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
            // Allowlist deserialization on the RMI registry (must be set before createRegistry).
            // Anything outside RMI plumbing, String/Number and this package's Hello is rejected.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.lang.reflect.Proxy;java.rmi.**;sun.rmi.**;"
                            + "org.joychou.RMI.Hello;!*");
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            LocateRegistry.createRegistry(1099);
            Registry registry = LocateRegistry.getRegistry();
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

