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
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            // JEP 290 allowlist: the registry only deserializes the types needed to bind/lookup
            // a Hello stub; every other class (gadget chains) is rejected. Must be set before createRegistry.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.reflect.Proxy;java.rmi.Remote;java.rmi.server.*;"
                            + "sun.rmi.server.**;sun.rmi.transport.**;org.joychou.RMI.Hello;!*");
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

