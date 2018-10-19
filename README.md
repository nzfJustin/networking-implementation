UCLA CS118 Project 1 (Simple Router)
====================================

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## TODO

    #################################################################
    ##                                                             ##
    ## For this project, first of all I checked all functions      ##
    ## in other files to understand how to implement them. Then    ##
    ## I use findIfaceByName to get the network interface and      ##
    ## if the packet type is neither ARP or IPv4, then I drop it   ##
    ## if the etherhrd is ARP, then we use the OP to check if      ##
    ## it is a ARP request or ARP reply. If it is a ARP request,   ##
    ## I use prepareForReplyARP function to prepare for reply ARP  ##
    ## If it is ARP reply, I use ResponseARP to do sender's        ##
    ## IP-MAC mapping and then I iterate the pending packet queue  ##
    ## to see whether we get dest MAC address for any queued packet##
    ## if so, we forward the packet to the client and remove the   ##
    ## request, we also need to decrement these packet's ttl to    ##
    ## see whether thet are expired.                               ##
    ## If the ethertype shows that the packet is IPv4, then I use  ##
    ## function packetCheck to check it's checksum and length, any ##
    ## unsatisfied packet will be dropped. Then I check Packet's   ##
    ## destination MAC address, if it is router's MAC address, then##
    ## drop the packet. Otherwise, I use function forwardThePacket ##  
    ## to forward the packet to the destination client             ##                            
    #################################################################
