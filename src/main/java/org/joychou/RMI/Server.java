package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;


public class Server implements Hello {

    /** Registry deserialization allowlist: only what is needed to bind the Hello stub; everything else rejected. */
    private static final String REGISTRY_FILTER =
            "java.lang.String;java.lang.Number;java.lang.reflect.Proxy;java.rmi.Remote;"
                    + "java.rmi.server.**;sun.rmi.server.**;sun.rmi.transport.**;"
                    + "org.joychou.RMI.Hello;!*";

    /** Listens on the loopback interface only, so the registry is not exposed to the network. */
    private static final class LoopbackSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        }
    }

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            // Must be set before the registry is created. Always enforced (not overridable by a pre-set value).
            System.setProperty("sun.rmi.registry.registryFilter", REGISTRY_FILTER);

            RMIServerSocketFactory loopback = new LoopbackSocketFactory();
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, loopback);
            Registry registry = LocateRegistry.createRegistry(1099, null, loopback);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}
