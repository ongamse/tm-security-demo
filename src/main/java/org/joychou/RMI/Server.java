package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    /** Server socket factory that only accepts connections on the loopback interface. */
    private static final class LoopbackServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof LoopbackServerSocketFactory;
        }

        @Override
        public int hashCode() {
            return LoopbackServerSocketFactory.class.hashCode();
        }
    }

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
            // Loopback-only: both the exported object and the registry listen on 127.0.0.1, so the
            // service is never reachable from other hosts.
            System.setProperty("java.rmi.server.hostname", "127.0.0.1");
            RMIServerSocketFactory loopbackFactory = new LoopbackServerSocketFactory();
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

