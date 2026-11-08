package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            // Restrict what the registry may deserialize (JEP 290) so a crafted bind/rebind
            // payload cannot trigger gadget chains. Must be set before the registry is created.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.lang.reflect.Proxy;java.rmi.Remote;"
                            + "java.rmi.server.**;java.rmi.activation.ActivationID;"
                            + "sun.rmi.server.**;sun.rmi.transport.**;!*");
            // Loopback only: stubs advertise 127.0.0.1 and every listening socket is bound to
            // the loopback interface, so the registry is not reachable from other hosts.
            System.setProperty("java.rmi.server.hostname", "127.0.0.1");
            // Never allow loading classes from a remote codebase.
            System.setProperty("java.rmi.server.useCodebaseOnly", "true");
            RMIServerSocketFactory loopbackFactory = new RMIServerSocketFactory() {
                @Override
                public ServerSocket createServerSocket(int port) throws IOException {
                    return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
                }
            };
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, loopbackFactory);
            Registry registry = LocateRegistry.createRegistry(1099, null, loopbackFactory);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

