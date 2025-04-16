# IP-TCP

# IP

## Abstraction and Layer Separation
- A major focus while developing was to keep all the major layers of the network stack independent and as loosely coupled as possible.
- The guiding principle was that if we change/add our protocol the IPStack should still be able to serve the new protocol. Similarly, we should be able to replace our network layer or link layer with another implementation and the system should still stay intact.
- The 3 major abstractions to this end were the Link Layer, Network Layer, and Protocol Layer.

### Link Layer
- This consists of all interfaces.
- It has been designed in a way that more interfaces could be added both to the router and host.
- Each interface runs on a separate thread (go routine) and listens for packets.

### Network Layer
- This is the central part of this project where most of the development happened.
- It sits on top of the Link Layer and uses the Link Layer to send/receive the UDP datagrams.
- It provides general functionality to send, record, and forward IP packets. Any protocol that needs to send packets will interact with this and not the Link Layer.
- The routing table is part of this layer.
    - The next hop for a packet is decided by logic residing here and using the routing table.
    - It is also responsible for checking for stale entries and removing them.
    - But it is not responsible for any RIP functionality and thus it was decided not to send a trigger update when deleting a route and letting the information flow on protocol level.
- The routing table is protected by a mutex as race conditions could arise b/w thread responsible for cleaning the table and IP sends functionality using the table or RIP protocol updating the table.

### Protocol
- This leverages IP Stack to build functionalities like test command and RIP.
- All protocols that need to use the IP Stack are passed the struct so they can use the methods.

## Other Design Decisions
- Both `vrouter` and `vhost` are identical and could very well just have been a single binary. The behavior is controlled based on the Routing Protocol defined in the config, this is to emulate real-world systems.
- The threads primarily being used are
    - A thread for each interface where it listens for UDP packets and sends them to IP Stack to handle and call the appropriate handler based on protocol
    - A thread for Periodic RoutingTable cleanup, checks regularly for timed-out entries. Almost like garbage collection.
    - A thread for Periodic RIP updates. Send RIP packets on all interfaces regularly.
- Register Handler is also implemented wherein the IPStack has a registry (Hash Map) of protocol number to receive handler. One can register their protocol and the handler will be called when a packet is received.
- When an IP packet is received
    The header is parsed.
    - Checksum verified, drop on failure.
    - TTL is decreased, if 0 and still not at the destination then the packet is dropped.
    - Destination is checked if it is one of the interfaces of the node.
    - If at destination then the correct handler as registered in the Handler Registry is called.
    - Else packet is forwarded with updated checksum (as TTL decreased).