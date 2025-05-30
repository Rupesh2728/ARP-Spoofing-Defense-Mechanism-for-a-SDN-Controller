from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
from pox.lib.recoco import Timer
import time
import pox.lib.packet as pkt

log = core.getLogger()

# Global host table for IP-MAC mappings across all switches
global_hosts = {}  # {IPAddr: EthAddr}

# Global MAC to switch-port mapping
global_mac_to_port = {}  # {MAC: (dpid, port)}

# Global switch connections tracker
switches = {}  # {dpid: connection}

# Global switch interconnections
switch_links = {}  # {(src_dpid, src_port): (dst_dpid, dst_port)}

# Global blacklist for detected spoofers
blacklisted_macs = set()

# Last time a packet was flooded - to prevent flood storms
last_flood_time = {}  # {dpid: {dst_mac: timestamp}}

# Time between allowed flooding (in seconds)
FLOOD_DELAY = 1

# Track when hosts were last seen (for timeout)
host_last_seen = {}  # {mac: timestamp}

def handle_dhcp_lease(event):
    """Handle DHCP lease events to update the global IP-MAC mapping."""
    log.info(f"DHCP Lease: IP {event.ip} assigned to MAC {event.host_mac}")
    if event.ip and event.host_mac:
        global_hosts[str(event.ip)] = str(event.host_mac)
        host_last_seen[str(event.host_mac)] = time.time()
        log.info(f"Added to global hosts table: {event.ip} -> {event.host_mac}")

class ARP_Spoof_Detection(object):
    """
    Handler for ARP spoofing detection and prevention on a per-switch basis,
    with awareness of the global state.
    """
    def __init__(self, connection, transparent=False):
        self.connection = connection
        self.transparent = transparent
        self.dpid = connection.dpid
        self.mac_to_port = {}  # Local MAC to port mapping for this switch
        self.last_spoof_attempt = {}  # Track repeated spoofing attempts
        self.arp_cache = {}  # Local ARP cache for this switch {IP: (MAC, expiry_time)}
        self.switch_ports = set()  # Ports that are connected to other switches
        
        # Add this switch to global switches dictionary
        switches[self.dpid] = connection
        
        # Initialize flood tracking for this switch
        if self.dpid not in last_flood_time:
            last_flood_time[self.dpid] = {}
        
        # Register for OpenFlow events
        connection.addListeners(self)
        
        # Discover switch topology - send LLDP-like packets on all ports
        self.discover_topology()
        
        # Install flow rules for ARP and DHCP packets
        self.add_flow_rule(arp_type=pkt.ethernet.ARP_TYPE)
        self.add_flow_rule(nw_proto=17, tp_src=67, tp_dst=68)
        
        # Apply blacklist to this switch
        for mac in blacklisted_macs:
            self.block_mac(mac)
        
        log.info(f"ARP Spoof Detection initialized on switch {dpid_to_str(self.dpid)}")
        
        # Schedule periodic topology discovery
        Timer(10, self.discover_topology, recurring=True)

    def discover_topology(self):
        """Send discovery packets on all ports to identify switch connections."""
        # Get port info
        msg = of.ofp_stats_request(body=of.ofp_port_stats_request())
        self.connection.send(msg)
        # Wait for reply and then send discovery packets
        Timer(1, self._send_discovery_packets, recurring=False)

    def _send_discovery_packets(self):
        """Send specially crafted packets on all ports to detect switch-to-switch links."""
        for port in range(1, 29):  # Assuming max 28 ports
            # Create discovery packet with special MAC to identify this switch
            discovery_mac = "de:ad:be:ef:{:02x}:{:02x}".format(self.dpid & 0xff, port & 0xff)
            
            # Create packet out message
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=port))
            
            # Create discovery ethernet packet
            e = ethernet()
            e.dst = EthAddr("ff:ff:ff:ff:ff:ff")
            e.src = EthAddr(discovery_mac)
            e.type = 0x8999  # Custom type for discovery
            
            msg.data = e.pack()
            self.connection.send(msg)
            log.debug(f"S{self.dpid}: Sent discovery packet on port {port}")

    def add_flow_rule(self, arp_type=None, nw_proto=None, tp_src=None, tp_dst=None):
        """Add a flow rule to the switch."""
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        
        if arp_type:
            msg.match.dl_type = arp_type
        if nw_proto and tp_src and tp_dst:
            msg.match.dl_type = 0x0800
            msg.match.nw_proto = nw_proto
            msg.match.tp_src = tp_src
            msg.match.tp_dst = tp_dst
            
        msg.idle_timeout = of.OFP_FLOW_PERMANENT
        msg.hard_timeout = of.OFP_FLOW_PERMANENT
        msg.priority = 65535  # High priority
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg)

    def block_mac(self, mac):
        """Block all traffic from a specific MAC address."""
        log.warning(f"Blocking all traffic from MAC {mac} on switch {dpid_to_str(self.dpid)}")
        
        # Create a flow rule to drop all packets from this MAC
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_src=EthAddr(mac))
        msg.priority = 65535  # Highest priority
        msg.idle_timeout = 300  # Block for 5 minutes
        msg.hard_timeout = 300
        # No actions means drop
        self.connection.send(msg)

    def handle_spoof(self, mac, event, packet):
        """Handle a detected spoofing attempt."""
        current_time = time.time()
        if mac in self.last_spoof_attempt and current_time - self.last_spoof_attempt[mac] < 60:
            log.warning(f"Repeated Spoof Attempt Detected: MAC {mac} on switch {dpid_to_str(self.dpid)}")
        self.last_spoof_attempt[mac] = current_time
        log.warning(f"Spoofing Detected: MAC {mac} is malicious on switch {dpid_to_str(self.dpid)}")
        
        # Add to global blacklist
        blacklisted_macs.add(mac)
        
        # Block on all switches
        for dpid, connection in switches.items():
            # For the current switch, use the event info
            if dpid == self.dpid:
                actions = []  # No actions means drop
                msg = of.ofp_flow_mod(
                    command=of.OFPFC_ADD,
                    priority=65535,
                    idle_timeout=300,
                    hard_timeout=300,
                    match=of.ofp_match(dl_src=EthAddr(mac)),
                    actions=actions
                )
                event.connection.send(msg)
            else:
                # For other switches, create a general block rule
                sw = switches.get(dpid)
                if sw:
                    msg = of.ofp_flow_mod()
                    msg.match = of.ofp_match(dl_src=EthAddr(mac))
                    msg.priority = 65535
                    msg.idle_timeout = 300
                    msg.hard_timeout = 300
                    # No actions means drop
                    sw.send(msg)
        
        log.info(f"Blocked MAC {mac} on all switches for 5 minutes")

    def _handle_PacketIn(self, event):
        """Handle packet in events from the switch."""
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        
        eth_packet = packet.find('ethernet')
        in_port = event.port
        
        # Check for discovery packets
        if eth_packet.type == 0x8999 and eth_packet.src.toStr().startswith("de:ad:be:ef"):
            # This is a discovery packet from another switch
            # Parse the source switch DPID and port from the MAC
            src_dpid = int(eth_packet.src.toStr().split(":")[4], 16)
            src_port = int(eth_packet.src.toStr().split(":")[5], 16)
            
            # Record switch-to-switch link
            switch_links[(src_dpid, src_port)] = (self.dpid, in_port)
            switch_links[(self.dpid, in_port)] = (src_dpid, src_port)
            
            # Mark this port as a switch port
            self.switch_ports.add(in_port)
            
            log.info(f"Discovered switch link: S{src_dpid}:{src_port} <-> S{self.dpid}:{in_port}")
            return
        
        # Log the packet
        log.debug(f"S{self.dpid}: {eth_packet.src} -> {eth_packet.dst} on port {in_port}")
        
        # Drop packets from blacklisted MACs
        if str(eth_packet.src) in blacklisted_macs:
            log.debug(f"Dropping packet from blacklisted MAC: {eth_packet.src}")
            return
            
        # Update MAC to port mapping
        self.mac_to_port[eth_packet.src] = in_port
        
        # Update host last seen timestamp
        host_last_seen[eth_packet.src] = time.time()
        
        # Update global MAC to switch-port mapping if not a switch port
        if in_port not in self.switch_ports:
            global_mac_to_port[eth_packet.src] = (self.dpid, in_port)
            log.debug(f"Updated global MAC table: {eth_packet.src} -> S{self.dpid}:{in_port}")
        
        if packet.type == packet.ARP_TYPE:
            self.handle_arp(packet, event)
        elif packet.type == packet.IP_TYPE:
            self.handle_ip(packet, event)
        else:
            self.forward_packet(packet, event)

    def handle_arp(self, packet, event):
        """Handle ARP packets for spoofing detection."""
        arp_packet = packet.find('arp')
        # hwsrc - MAC address of sender (hardware source)
        # protosrc - IP address of the sender (Protocol source)
        # hwsdst - Destination MAC address  (hardware destination)
        # protodst - Destination IP address  (Protocol destination)
        
        if str(arp_packet.hwsrc) in blacklisted_macs:
            log.warning(f"Dropping ARP from blacklisted MAC: {arp_packet.hwsrc}")
            return  # Drop packet from blacklisted MAC
            
        if arp_packet.opcode == arp.REQUEST:
            log.debug(f"S{self.dpid}: ARP Request: {arp_packet.protosrc} asks for {arp_packet.protodst}")
            
            # Cache the requester's IP-MAC mapping (with timeout)
            self.arp_cache[str(arp_packet.protosrc)] = (str(arp_packet.hwsrc), time.time() + 3600)  # 1 hour cache
            
            # Update global hosts table
            global_hosts[str(arp_packet.protosrc)] = str(arp_packet.hwsrc)
            
            # Check if we already know the target's MAC
            if str(arp_packet.protodst) in global_hosts:
                target_mac = global_hosts[str(arp_packet.protodst)]
                if target_mac in global_mac_to_port:
                    target_dpid, target_port = global_mac_to_port[target_mac]
                    log.debug(f"We know target {arp_packet.protodst} is at MAC {target_mac} on S{target_dpid}:{target_port}")
                    
                    # If the target is on another switch, we need to forward the ARP request
                    if target_dpid != self.dpid:
                        log.debug(f"Target is on different switch S{target_dpid}, forwarding ARP request")
                        self.forward_to_switch(packet, event, target_dpid)
                    else:
                        # Target is on this switch, forward directly to the target port
                        self.send_packet(event, target_port)
                        return
            
            # We don't know the target's location, flood to all non-switch ports
            # For ARP requests, use a modified flooding approach to reduce broadcast storms
            self.controlled_flood(event, packet)
            return
            
        elif arp_packet.opcode == arp.REPLY:
          log.debug(f"S{self.dpid}: ARP Reply: {arp_packet.hwsrc} claims {arp_packet.protosrc}")
    
           # Check for spoofing in global host table
          if str(arp_packet.protosrc) in global_hosts:
             if global_hosts[str(arp_packet.protosrc)] != str(arp_packet.hwsrc):
                 log.warning(f"ARP Spoofing Detected: {arp_packet.hwsrc} is claiming {arp_packet.protosrc} (expected {global_hosts[str(arp_packet.protosrc)]})")
                 self.handle_spoof(str(arp_packet.hwsrc), event, packet)
                 return  # Drop packet
    
         # If not detected as spoofing, update our mappings
          global_hosts[str(arp_packet.protosrc)] = str(arp_packet.hwsrc)
          self.arp_cache[str(arp_packet.protosrc)] = (str(arp_packet.hwsrc), time.time() + 3600)  # 1 hour cache
    
    # For ARP replies, forward directly to the requester if known
          if str(arp_packet.protodst) in global_hosts:
             req_mac = global_hosts[str(arp_packet.protodst)]
             if req_mac in self.mac_to_port:
                req_port = self.mac_to_port[req_mac]
                log.debug(f"Forwarding ARP reply directly to requester at port {req_port}")
                self.send_packet(event, req_port)
                return
             elif req_mac in global_mac_to_port:
                req_dpid, req_port = global_mac_to_port[req_mac]
                if req_dpid != self.dpid:
                # Find the port that connects to the switch where the requester is
                   out_port = self.get_switch_port_to_dpid(req_dpid)
                   if out_port is not None:
                      log.debug(f"Forwarding ARP reply to switch {req_dpid} via port {out_port}")
                      self.send_packet(event, out_port)
                      return
                   else:
                    log.debug(f"No direct path to switch {req_dpid}, controlled flooding")
    
    # If we don't know where the requester is, use controlled flooding
        self.controlled_flood(event, packet)

    def get_switch_port_to_dpid(self, target_dpid):
        """Find the port on this switch that connects to the target switch."""
        for (src_dpid, src_port), (dst_dpid, dst_port) in switch_links.items():
            if src_dpid == self.dpid and dst_dpid == target_dpid:
                return src_port
        return None

    def forward_to_switch(self, packet, event, target_dpid):
        """Forward a packet to another switch using the known links."""
        # Check if there's a direct link to the target switch
        out_port = self.get_switch_port_to_dpid(target_dpid)
        if out_port is not None:
            log.debug(f"S{self.dpid}: Forwarding packet to S{target_dpid} via port {out_port}")
            self.send_packet(event, out_port)
            return True
        
        # No direct link, try to find a multi-hop path 
        # For now, flood to all switch ports as a fallback
        log.debug(f"S{self.dpid}: No direct path to S{target_dpid}, forwarding to all switch ports")
        self.flood_to_switches(event)
        return False

    def flood_to_switches(self, event):
        """Flood a packet only to ports that connect to other switches."""
        if not self.switch_ports:
            log.debug(f"S{self.dpid}: No switch ports known, can't flood to switches")
            return
            
        for port in self.switch_ports:
            if port != event.port:  # Don't send back to the source
                msg = of.ofp_packet_out()
                msg.in_port = event.port
                
                if event.ofp.buffer_id != of.NO_BUFFER and port == list(self.switch_ports)[0]:
                    msg.buffer_id = event.ofp.buffer_id
                else:
                    if event.ofp.data:
                        msg.data = event.ofp.data
                        
                msg.actions.append(of.ofp_action_output(port=port))
                self.connection.send(msg)
                log.debug(f"S{self.dpid}: Forwarding packet to switch port {port}")

    def controlled_flood(self, event, packet):
        """Flood a packet with rate limiting to prevent broadcast storms."""
        eth_packet = packet.find('ethernet')
        dst_mac = eth_packet.dst
        current_time = time.time()
        
        # Check if we've recently flooded a packet to this destination
        if dst_mac in last_flood_time[self.dpid]:
            last_time = last_flood_time[self.dpid][dst_mac]
            if current_time - last_time < FLOOD_DELAY:
                log.debug(f"S{self.dpid}: Suppressing flood to {dst_mac}, too recent")
                return
        
        # Update the last flood time for this destination
        last_flood_time[self.dpid][dst_mac] = current_time
        
        # Don't flood to ports that connect to other switches if we know
        # this is an ARP request for a host and we haven't seen that host on 
        # those switches
        arp_packet = packet.find('arp')
        if arp_packet and arp_packet.opcode == arp.REQUEST:
            target_ip = str(arp_packet.protodst)
            # If we know where the target is, don't flood everywhere
            if target_ip in global_hosts:
                target_mac = global_hosts[target_ip]
                if target_mac in global_mac_to_port:
                    target_dpid, target_port = global_mac_to_port[target_mac]
                    # Only forward to the switch where the target is connected
                    if target_dpid != self.dpid:
                        out_port = self.get_switch_port_to_dpid(target_dpid)
                        if out_port is not None:
                            log.debug(f"S{self.dpid}: Forwarding ARP request to specific switch {target_dpid}")
                            self.send_packet(event, out_port)
                            return
        
        # If we don't know where to send, or it's not an ARP request
        # Flood to all non-source ports, but use a more controlled approach
        port_list = []
        for port in range(1, 29):  # Assuming max 28 ports
            if port != event.port:
                port_list.append(port)
        
        log.debug(f"S{self.dpid}: Flooding packet to {len(port_list)} non-source ports")
        
        # Use buffer_id if possible
        if event.ofp.buffer_id != of.NO_BUFFER and port_list:
            # Send to first port using buffer_id
            msg = of.ofp_packet_out()
            msg.in_port = event.port
            msg.buffer_id = event.ofp.buffer_id
            msg.actions.append(of.ofp_action_output(port=port_list[0]))
            self.connection.send(msg)
            
            # For remaining ports, send using data
            for port in port_list[1:]:
                if event.ofp.data:
                    msg = of.ofp_packet_out()
                    msg.in_port = event.port
                    msg.data = event.ofp.data
                    msg.actions.append(of.ofp_action_output(port=port))
                    self.connection.send(msg)
        else:
            # No buffer ID, send using data to all ports
            for port in port_list:
                if event.ofp.data:
                    msg = of.ofp_packet_out()
                    msg.in_port = event.port
                    msg.data = event.ofp.data
                    msg.actions.append(of.ofp_action_output(port=port))
                    self.connection.send(msg)

    def flood_packet(self, event):
        """Flood a packet to all ports except the incoming port, with optimization."""
        in_port = event.port
        
        # Determine list of ports to flood to
        # Avoid sending to the source port
        flood_ports = []
        
        # First, get all active ports (excluding the incoming port)
        msg = of.ofp_stats_request(body=of.ofp_port_stats_request())
        self.connection.send(msg)
        
        # Since we can't get the reply immediately, we'll flood to all possible ports
        for port in range(1, 29):  # Assuming max 28 ports
            if port != in_port:
                flood_ports.append(port)
        
        if not flood_ports:
            return  # No ports to flood to
            
        log.debug(f"S{self.dpid}: Flooding packet to {len(flood_ports)} non-source ports")
        
        # Use buffer_id if possible for efficiency
        if event.ofp.buffer_id != of.NO_BUFFER and flood_ports:
            # Send to first port using buffer_id
            msg = of.ofp_packet_out()
            msg.in_port = in_port
            msg.buffer_id = event.ofp.buffer_id
            msg.actions.append(of.ofp_action_output(port=flood_ports[0]))
            self.connection.send(msg)
            
            # Send to remaining ports using packet data
            flood_ports = flood_ports[1:]
        
        # Send to all remaining ports
        if flood_ports and event.ofp.data:
            for port in flood_ports:
                msg = of.ofp_packet_out()
                msg.in_port = in_port
                msg.data = event.ofp.data
                msg.actions.append(of.ofp_action_output(port=port))
                self.connection.send(msg)

    def handle_ip(self, packet, event):
        """Handle IP packets."""
        ip_packet = packet.find('ipv4')
        if ip_packet:
            # Update IP-MAC mapping from IP packets
            global_hosts[str(ip_packet.srcip)] = str(packet.src)
            host_last_seen[packet.src] = time.time()
            
            # More detailed logging for ping packets to help diagnose issues
            if ip_packet.protocol == 1:  # ICMP
                icmp_packet = ip_packet.find('icmp')
                if icmp_packet and icmp_packet.type == 8:  # ICMP Echo Request
                    log.info(f"S{self.dpid}: ICMP Echo Request from {ip_packet.srcip} to {ip_packet.dstip}")
                elif icmp_packet and icmp_packet.type == 0:  # ICMP Echo Reply
                    log.info(f"S{self.dpid}: ICMP Echo Reply from {ip_packet.srcip} to {ip_packet.dstip}")
            
        self.forward_packet(packet, event)

    def forward_packet(self, packet, event):
        """Forward packet using L2 learning switch logic with multi-switch awareness."""
        eth_packet = packet.find('ethernet')
        in_port = event.port
        
        # Drop packets from blacklisted MACs
        if str(eth_packet.src) in blacklisted_macs:
            log.debug(f"Dropping packet from blacklisted MAC: {eth_packet.src}")
            return
            
        # Learn the mapping of MAC to port
        self.mac_to_port[eth_packet.src] = in_port
        
        # Update global MAC to switch-port mapping if not a switch port
        if in_port not in self.switch_ports:
            global_mac_to_port[eth_packet.src] = (self.dpid, in_port)
            host_last_seen[eth_packet.src] = time.time()
            log.debug(f"Updated global MAC table: {eth_packet.src} -> S{self.dpid}:{in_port}")
        
        # Handle multicast/broadcast differently
        if eth_packet.dst.is_multicast:
            log.debug(f"S{self.dpid}: Handling multicast/broadcast packet")
            self.controlled_flood(event, packet)
            return
        
        # Check if we know which port to send it to on this switch
        if eth_packet.dst in self.mac_to_port:
            out_port = self.mac_to_port[eth_packet.dst]
            log.debug(f"S{self.dpid}: Known destination {eth_packet.dst} on port {out_port}")
            self.send_packet(event, out_port)
            
            # Install a flow rule for future packets
            self.install_flow(event, out_port, eth_packet)
            return
        
        # Check if the destination is known on another switch
        if eth_packet.dst in global_mac_to_port:
            target_dpid, target_port = global_mac_to_port[eth_packet.dst]
            if target_dpid != self.dpid:
                log.debug(f"S{self.dpid}: Destination {eth_packet.dst} is on switch {target_dpid}")
                # The host is connected to a different switch
                out_port = self.get_switch_port_to_dpid(target_dpid)
                if out_port is not None:
                    log.debug(f"S{self.dpid}: Forwarding to S{target_dpid} via port {out_port}")
                    self.send_packet(event, out_port)
                    
                    # Install a flow rule for future packets to this destination
                    self.install_flow(event, out_port, eth_packet)
                    return
                else:
                    # No direct link, try to find a path through other switches
                    for link_src, link_dst in switch_links.items():
                        if link_src[0] == self.dpid and link_dst[0] == target_dpid:
                            out_port = link_src[1]
                            log.debug(f"S{self.dpid}: Found path to S{target_dpid} via port {out_port}")
                            self.send_packet(event, out_port)
                            self.install_flow(event, out_port, eth_packet)
                            return
                    
                    # Still no path found, flood to all switch ports as last resort
                    log.debug(f"S{self.dpid}: No path to S{target_dpid}, flooding to switch ports")
                    self.flood_to_switches(event)
                    return
        
        # We don't know where the destination is
        # Use controlled flooding to avoid broadcast storms
        log.debug(f"S{self.dpid}: Unknown destination {eth_packet.dst}, controlled flooding")
        self.controlled_flood(event, packet)

    def install_flow(self, event, out_port, eth_packet):
        """Install a flow rule for this MAC-port pair."""
        log.debug(f"S{self.dpid}: Installing flow: {eth_packet.src} -> {eth_packet.dst} on port {out_port}")
        
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(
            dl_src=eth_packet.src,
            dl_dst=eth_packet.dst
        )
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port=out_port))
        
        # Use buffer_id if possible for efficiency
        if event.ofp.buffer_id != of.NO_BUFFER:
            msg.buffer_id = event.ofp.buffer_id
        else:
            # No buffer ID, must include the data
            if event.ofp.data:
                msg.data = event.ofp.data
                
        self.connection.send(msg)

    def send_packet(self, event, out_port):
        """Send a packet out a specific port."""
        msg = of.ofp_packet_out()
        msg.in_port = event.port
        
        # Use buffer_id if possible for efficiency
        if event.ofp.buffer_id != of.NO_BUFFER:
            msg.buffer_id = event.ofp.buffer_id
        else:
            if event.ofp.data:
                msg.data = event.ofp.data
                
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)
        
        log.debug(f"S{self.dpid}: Sending packet to port {out_port}")

class l2_learning(object):
    """
    Main controller class that manages all connected switches and
    provides global state management.
    """
    def __init__(self):
        # Listen for core OpenFlow events
        core.openflow.addListeners(self)
        
        # Set up DHCP integration if available
        if core.hasComponent('DHCPD'):
            log.info("DHCPD detected. Registering DHCP Lease listener.")
            core.DHCPD.addListenerByName('DHCPLease', handle_dhcp_lease)
        else:
            log.warning("DHCPD not detected. Ensure proto.dhcpd is running for accurate IP-MAC mapping.")
            
        # Set up a timer to periodically check and clean expired entries
        Timer(60, self._timer_func, recurring=True)
        
        log.info("Multi-Switch Controller Initialized")

    def _handle_ConnectionUp(self, event):
        """Handle a new switch connection."""
        log.info(f"Switch {dpid_to_str(event.dpid)} connected")
        
        # Create a new ARP spoof detection instance for this switch
        ARP_Spoof_Detection(event.connection)

    def _timer_func(self):
        """Periodic cleanup of stale entries and other maintenance tasks."""
        # Clean up any stale entries in our tables
        current_time = time.time()
        
        # Clean old flood records to allow periodic retries
        for dpid in last_flood_time:
            # Remove flood records older than 5 minutes
            for mac in list(last_flood_time[dpid].keys()):
                if current_time - last_flood_time[dpid][mac] > 300:
                    del last_flood_time[dpid][mac]
        
        # Clean stale MAC-to-port entries (hosts not seen in 30 minutes)
        for mac in list(host_last_seen.keys()):
            if current_time - host_last_seen[mac] > 1800:  # 30 minutes
                if mac in global_mac_to_port:
                    log.info(f"Removing stale MAC-to-port entry for {mac}")
                    del global_mac_to_port[mac]
                # Don't remove from host_last_seen to track when it was last removed
        
        # Clean blacklist periodically (after 1 hour)
        expired_macs = set()
        for mac in blacklisted_macs:
            # In a real implementation, you'd track when each MAC was blacklisted
            # For now, we're just keeping the blacklist intact
            pass
            
        for mac in expired_macs:
            blacklisted_macs.remove(mac)
            log.info(f"Removed {mac} from blacklist - timeout expired")

def launch():
    """Launch the module."""
    core.registerNew(l2_learning)
    log.info("Multi-Switch L2 Learning with ARP Spoof Detection Launched.")