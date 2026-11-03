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
            // Allowlist-only deserialization filter for the registry (JEP 290): reject every class that a
            // registry call legitimately does not need, so remote gadget-chain payloads cannot be deserialized.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.lang.reflect.Proxy;java.rmi.Remote;"
                            + "java.rmi.server.RemoteObject;java.rmi.server.RemoteStub;java.rmi.server.UnicastRemoteObject;"
                            + "java.rmi.server.ObjID;java.rmi.server.UID;java.rmi.activation.ActivationID;"
                            + "sun.rmi.server.*;sun.rmi.transport.*;org.joychou.RMI.Hello;!*");
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

