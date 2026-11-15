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
            // JEP 290: the registry may only deserialize Strings from remote callers (lookup names);
            // no remote object/class is ever accepted from the network. Must be set before the registry class loads.
            System.setProperty("sun.rmi.registry.registryFilter", "java.lang.String;!*");
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            // Bind the fixed server-side object through the local registry instance (no remote call,
            // no deserialization); remote bind/rebind attempts are rejected by the filter above.
            Registry registry = LocateRegistry.createRegistry(1099);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

