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
            // JEP 290 registry deserialization allowlist (must be set before the registry is created):
            // only types needed to bind/lookup a remote stub are accepted, everything else is rejected.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "maxdepth=5;java.lang.String;java.lang.Number;java.lang.reflect.Proxy;"
                            + "java.rmi.Remote;org.joychou.RMI.Hello;java.rmi.server.**;sun.rmi.server.**;sun.rmi.transport.**;!*");
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

