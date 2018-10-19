/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"  // ethertype
#include "core/protocol.hpp"   // include <vector>
#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  // Find input network interface using already given function
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }
  std::cerr << getRoutingTable() << std::endl;
  print_hdrs(packet);
  std::vector<unsigned char> ether_hder(packet.begin(), packet.begin() + sizeof(ethernet_hdr));
  uint8_t* packet_ether_hr = ether_hder.data();
  unsigned char* complete_packet = (unsigned char*) malloc(packet.size());
  uint8_t* whole_packet = reinterpret_cast<uint8_t*>(memcpy(complete_packet, packet.data(), packet.size()));

  // get ethernet header and check the eth_type field.
  // Ignore Ethernet frames other than ethernet type ARP and IPv4.
  if (ethertype(packet_ether_hr) != ethertype_arp && ethertype(packet_ether_hr) != ethertype_ip) {
    std:: cerr << "Package type " << ethertype(packet_ether_hr) << " unknown, drop the package." << std::endl;
    return;
  }
  // 3.eth_type is ARP, check ARP operation (ARP request/ARP response):
  else if (ethertype(packet_ether_hr) == ethertype_arp){
    unsigned char* packet_Arp_hdr = (unsigned char*) malloc(sizeof(arp_hdr));
    arp_hdr* packet_arp_hdr = reinterpret_cast<arp_hdr*>(memcpy(packet_Arp_hdr, packet.data()+ sizeof(ethernet_hdr), sizeof(arp_hdr)));
    // ARP Request packet:
    if (ntohs(packet_arp_hdr->arp_op) == arp_op_request) 
    {
      prepareForReplyARP( packet_arp_hdr, iface);
    }
    // If ARP Response packet
    else if (ntohs(packet_arp_hdr->arp_op) == arp_op_reply)
    {
      if (packet_arp_hdr->arp_tip == iface->ip){
           ResponseARP(packet_arp_hdr, iface);
      }
    }
    else {
      std:: cerr << "Package arp_op unknown, drop the package." << std::endl;
      return;
    }
  }
  // If eth_type is IPv4 packet to be forwarded to a next-hop IP address
  else if (ethertype(packet_ether_hr) == ethertype_ip) {
    // get the package ip header
    std:: cout << "IP type" << std::endl;
    ip_hdr *packet_ip_hdr = (ip_hdr *) (whole_packet + sizeof(ethernet_hdr));
    // a. verify its checksum and the minimum length of an IP packet, discard invalid packets
    packetCheck(packet_ip_hdr);
    // b. if packet is destined to router's IP addresses of the router 
    std::set<Interface>::const_iterator InfIterator;
    for (InfIterator = this->m_ifaces.begin(); InfIterator != this->m_ifaces.end(); ++InfIterator) {
      if (packet_ip_hdr->ip_dst == InfIterator->ip) {
        std::cerr << "Packet destined router, Drop." << std:: endl;
        return;
      }
    }
    // c. for packets to be forwarded:
    forwardThePacket(packet_ip_hdr, packet_ether_hr, iface, whole_packet, packet);
   }
}
void SimpleRouter::prepareForReplyARP(arp_hdr* packet_arp_hdr, const Interface* iface)
{
      Buffer mac_vec(packet_arp_hdr->arp_sha,
        packet_arp_hdr->arp_sha + sizeof packet_arp_hdr->arp_sha / sizeof packet_arp_hdr->arp_sha[0]);
      // record sender's MAC-IP
      std::shared_ptr<ArpRequest> ArpRequest_pointer =
        m_arp.insertArpEntry(mac_vec, packet_arp_hdr->arp_sip);
      std:: cout << "Record the IP-MAC mapping into cache." << std::endl;
      // we are the ARPed
      if (packet_arp_hdr->arp_tip == iface->ip) {
        uint8_t* reply_pckt = (uint8_t *) malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        ethernet_hdr* new_etherHeader = (ethernet_hdr*)reply_pckt;
        arp_hdr* new_arpHeader = (arp_hdr*)(reply_pckt + sizeof(ethernet_hdr));
        std:: cout << "ARP reply packet prepared." << std::endl;
        // prepare Ethernet header
        memcpy(new_etherHeader->ether_dhost, packet_arp_hdr->arp_sha, ETHER_ADDR_LEN);
        copy(iface->addr.begin(), iface->addr.end(), new_etherHeader->ether_shost);
        new_etherHeader->ether_type = htons(ethertype_arp); // host to network
        // prepare ARP header
        new_arpHeader->arp_hrd = packet_arp_hdr->arp_hrd;
        new_arpHeader->arp_pro = packet_arp_hdr->arp_pro;
        new_arpHeader->arp_hln = packet_arp_hdr->arp_hln;
        new_arpHeader->arp_pln = packet_arp_hdr->arp_pln;
        new_arpHeader->arp_op = htons(arp_op_reply);
        copy(iface->addr.begin(), iface->addr.end(), new_arpHeader->arp_sha);
        new_arpHeader->arp_sip = iface->ip;
        memcpy(new_arpHeader->arp_tha, packet_arp_hdr->arp_sha, ETHER_ADDR_LEN);
        new_arpHeader->arp_tip = packet_arp_hdr->arp_sip;
        //buffer the packet 
        Buffer ARP_reply(reply_pckt, reply_pckt + sizeof(ethernet_hdr) + sizeof(arp_hdr));
        print_hdrs(ARP_reply);
        //send the packet 
        sendPacket(ARP_reply, iface->name);
        free(reply_pckt);
        free(packet_arp_hdr);
        }
   }

void SimpleRouter::ResponseARP(arp_hdr* packet_arp_hdr, const Interface* iface)
{
 if (packet_arp_hdr->arp_tip == iface->ip){
        // convert sha from array format to vector
        Buffer arp_sha_vec(packet_arp_hdr->arp_sha, packet_arp_hdr->arp_sha +
          sizeof packet_arp_hdr->arp_sha / sizeof packet_arp_hdr->arp_sha[0]);
        // MAC-IP mapping of the sender 
        std::shared_ptr<ArpRequest> ArpRequest_pointer = m_arp.insertArpEntry(arp_sha_vec, packet_arp_hdr->arp_sip);
        std:: cout << "Record the IP-MAC mapping into cache." << std::endl;
        if (ArpRequest_pointer){
          if (!ArpRequest_pointer->packets.empty()){
            std::list<PendingPacket> m_packets = ArpRequest_pointer->packets;
            // iterate through all pending packets in the queue 
            std::list<PendingPacket>::const_iterator PendIterator;
            for (PendIterator = m_packets.begin(); PendIterator != m_packets.end(); ++PendIterator) {
              PendingPacket temp = *PendIterator;
              // unwrap the packet to see its inside
              unsigned char* unwrap_packet = (unsigned char*) malloc(temp.packet.size());
              uint8_t* unwrapped_packet = reinterpret_cast<uint8_t*>(memcpy(unwrap_packet,
                 temp.packet.data(), temp.packet.size()));
              // cut and get Ethernet header
              ethernet_hdr* pend_packet_etherhdr = (ethernet_hdr *)(unwrapped_packet);
              // cut and get ip header
              ip_hdr* pending_packet_iphdr = (ip_hdr *)(unwrapped_packet + sizeof(ethernet_hdr));
              // modify Ethernet Header
              memcpy(pend_packet_etherhdr->ether_shost, packet_arp_hdr->arp_tha, ETHER_ADDR_LEN);
              copy(arp_sha_vec.begin(), arp_sha_vec.end(), pend_packet_etherhdr->ether_dhost);
              pend_packet_etherhdr->ether_type = htons(ethertype_ip);
              // decrement ttl
              pending_packet_iphdr->ip_ttl =  pending_packet_iphdr->ip_ttl - 1;
              
              if (pending_packet_iphdr->ip_ttl > 0) {
                 // recalculate checksum
                 pending_packet_iphdr->ip_sum = 0;
                 pending_packet_iphdr->ip_sum = cksum(pending_packet_iphdr, sizeof(ip_hdr));
              }
              else {
                 std:: cerr << "drop expired packet." << std::endl;
                 return;
              }
              std::vector<unsigned char> resent_packet(unwrapped_packet, unwrapped_packet + temp.packet.size());
              std:: cout << "packet preview\n" << std::endl;
              print_hdrs(resent_packet);
              sendPacket(resent_packet, PendIterator->iface);
            }
            m_arp.removeRequest(ArpRequest_pointer);
          }
        }
        else{
           return;
        }
      } 
}
void SimpleRouter::packetCheck(ip_hdr* packet_ip_hdr)
{
   //check checksum
   uint16_t Checksum = packet_ip_hdr->ip_sum;
    packet_ip_hdr->ip_sum = 0;
    uint16_t Checksum_recomputation = cksum(packet_ip_hdr, sizeof(ip_hdr));
    if (Checksum != Checksum_recomputation){
      std:: cerr << "Package checksum failed, drop the packet." << std::endl;
      return;
    }
    else {
      std:: cout << "checksum correct!\n";
      packet_ip_hdr->ip_sum = Checksum_recomputation;
    }
    //check length 
     if (packet_ip_hdr->ip_len < sizeof(ip_hdr)) {
      std::cerr << "Drop the packet, length not satisfied" << std:: endl;
      return;
    }
}
void SimpleRouter::forwardThePacket(ip_hdr* packet_ip_hdr, uint8_t* packet_ether_hr, const Interface* iface,
uint8_t* whole_packet, const Buffer& packet)
{
     // use the Longest Prefix Match algorithm to find a next-hop IP address in the routing table ii.
    RoutingTableEntry possible_route = m_routingTable.lookup(ntohl(packet_ip_hdr->ip_dst));
    // check ARP cache if it has a MAC address mapped to the destination IP address for next-hop.
    std::shared_ptr<ArpEntry> valid_route = m_arp.lookup(possible_route.gw);
      // If a valid entry is found: proceed with handling the IP packet.
    if (valid_route) {
      // decrement time
      packet_ip_hdr->ip_ttl = packet_ip_hdr->ip_ttl - 1;
      if(packet_ip_hdr->ip_ttl > 0) {
         // checksum recompute 
         packet_ip_hdr->ip_sum = 0;
         packet_ip_hdr->ip_sum = cksum(packet_ip_hdr, sizeof(ip_hdr));
         // find outgoing interface
         const Interface *forward_interface = findIfaceByName(possible_route.ifName);
         // prepare new packet with new ethernet_header
         ethernet_hdr* forward_ether_hdr = (ethernet_hdr*) whole_packet;
         // Ethernet Header
         copy(forward_interface->addr.begin(), forward_interface->addr.end(), forward_ether_hdr->ether_shost);
         copy(valid_route->mac.begin(), valid_route->mac.end(), forward_ether_hdr->ether_dhost);
         forward_ether_hdr->ether_type = htons(ethertype_ip);
         std::vector<unsigned char> forwarding_packet(whole_packet, whole_packet + packet.size());
         // sent the packet
         std::cout << "we forward out a packet!\n";
         std:: cout << "forwarding packet" << std:: endl;
         print_hdrs(forwarding_packet);
         sendPacket(forwarding_packet, possible_route.ifName);
      }
      else {
         // expired packet, drop 
         std:: cerr << "drop expired packet." << std:: endl;
         return;
      }
    }
    // ARP request to discover the IP-MAC mapping.
    else {
      // queue the packet, waiting on this ARP request.
      std::shared_ptr<ArpRequest> arp_RequestPtr = m_arp.queueRequest(possible_route.dest,
         packet, possible_route.ifName);
      std::chrono::duration<double> diff;
      auto time_now = std::chrono::steady_clock::now();
      if (arp_RequestPtr->nTimesSent != 0) {
        diff = time_now - arp_RequestPtr->timeSent;
      }
      // send ARP request if never sent or one hasn’t been sent within the last second
      if (arp_RequestPtr->nTimesSent == 0 || diff.count() >= 1.0)
      {
        arp_RequestPtr->ip = possible_route.dest;
        arp_RequestPtr->nTimesSent = arp_RequestPtr->nTimesSent + 1;
        arp_RequestPtr->timeSent = std::chrono::steady_clock::now();
        // prepare ARP packet
        uint8_t* arp_RequestPacket = (uint8_t *) malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        ethernet_hdr* arp_EthernetHdr_R = (ethernet_hdr*) arp_RequestPacket;
        arp_hdr* arp_Hdr_R = (arp_hdr*) (arp_RequestPacket + sizeof(ethernet_hdr));
        // prepare Ethernet Header
        memcpy(arp_EthernetHdr_R->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
        copy(iface->addr.begin(), iface->addr.end(), arp_EthernetHdr_R->ether_shost);
        arp_EthernetHdr_R->ether_type = htons(ethertype_arp);
        // prepare ARP header
        arp_Hdr_R->arp_hrd = htons(arp_hrd_ethernet);
        arp_Hdr_R->arp_pro = htons(ethertype_ip);
        arp_Hdr_R->arp_hln = ETHER_ADDR_LEN;
        arp_Hdr_R->arp_pln = 0x04;
        arp_Hdr_R->arp_op = htons(arp_op_request);
        copy(iface->addr.begin(), iface->addr.end(), arp_Hdr_R->arp_sha);
        arp_Hdr_R->arp_sip = iface->ip;
        arp_Hdr_R->arp_tip = arp_RequestPtr->ip;
        // send packet
        std::vector<unsigned char> arp_request_packet(arp_RequestPacket,
          arp_RequestPacket + sizeof(ethernet_hdr) + sizeof(arp_hdr));
        print_hdrs(arp_request_packet);
        sendPacket(arp_request_packet, iface->name);
        free(arp_RequestPacket);
      }
    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
