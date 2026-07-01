#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    vlan_tci = -1
    # Check for VLAN tag (0x8200 in network byte order is b'\x82\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id, vlan_tci

def create_vlan_tag(ext_id, vlan_id):
    # Use EtherType = 8200h for our custom 802.1Q-like protocol.
    # PCP and DEI bits are used to extend the original VID.
    #
    # The ext_id should be the sum of all nibbles in the MAC address of the
    # host attached to the _access_ port. Ignore the overflow in the 4-bit
    # accumulator.
    #
    # NOTE: Include these 4 extensions bits only in the check for unicast
    #       frames. For multicasts, assume that you're dealing with 802.1Q.
    return struct.pack('!H', 0x8200) + \
           struct.pack('!H', ((ext_id & 0xF) << 12) | (vlan_id & 0x0FFF))

def function_on_different_thread():
    while True:
        time.sleep(1)

def calculate_mac_nibble_sum(mac_bytes):
    nibble_sum = 0
    for byte in mac_bytes:
        nibble_sum += (byte >> 4)
        nibble_sum += (byte & 0xF)
    return nibble_sum & 0xF

PPDU_DEST_MAC = b'\x01\x80\xc2\x00\x00\x00'
HPDU_DEST_MAC = b'\xff\xff\xff\xff\xff\xff'
HPDU_ETHER_TYPE = 0x0800
HPDU_DATA = b'\xff'
LLC_DSAP = 0x42
LLC_SSAP = 0x42
LLC_CONTROL = 0x03
PPDU_PROTOCOL_ID = 0x0002
PPDU_PROTOCOL_VERSION = 0
PPDU_TYPE = 0x80
HPDU_INTERVAL = 1
PSTP_HELLO_TIME = 2
STP_DEFAULT_PRIORITY = 32768
STP_COST_100MBPS = 19
PORT_STATE_BLOCKING = 0
PORT_STATE_FORWARDING = 1
PORT_TYPE_ACCESS = 0
PORT_TYPE_TRUNK = 1

def get_bridge_id(mac_bytes, priority):
    return struct.pack('!H', priority) + mac_bytes

def create_hpdu_packet(src_mac):
    frame = HPDU_DEST_MAC + src_mac
    frame += struct.pack('!H', HPDU_ETHER_TYPE)
    frame += HPDU_DATA

    if len(frame) < 60:
        frame += b'\x00' * (60 - len(frame))
    return frame, len(frame)

def create_ppdu_packet(stp_info, seq_num):
    flags = 0
    root_bridge_id = stp_info['root_bridge_id']
    root_path_cost = stp_info['root_path_cost']
    bridge_id = stp_info['bridge_id']
    port_id =0x8001
    message_age = 0
    max_age = 20
    hello_time = PSTP_HELLO_TIME
    forward_delay = 15

    ppdu_config =struct.pack('!B', flags)
    ppdu_config += root_bridge_id
    ppdu_config += struct.pack('!L', root_path_cost)
    ppdu_config += bridge_id
    ppdu_config += struct.pack('!H', port_id)
    ppdu_config += struct.pack('!H', message_age)
    ppdu_config += struct.pack('!H', max_age)
    ppdu_config += struct.pack('!H', hello_time)
    ppdu_config += struct.pack('!H', forward_delay)
    ppdu_header = struct.pack('!HBB', PPDU_PROTOCOL_ID, PPDU_PROTOCOL_VERSION, PPDU_TYPE)
    ppdu_header+= struct.pack('!L', seq_num % 100)

    llc_header = struct.pack('!BBB', LLC_DSAP, LLC_SSAP, LLC_CONTROL)
    llc_payload = ppdu_header + ppdu_config
    llc_length = len(llc_payload)

    src_mac = stp_info['switch_mac']
    frame = PPDU_DEST_MAC +src_mac
    frame += struct.pack('!H', llc_length + 3)
    frame += llc_header
    frame += llc_payload

    if len(frame) < 60:
        frame += b'\x00' * (60 - len(frame))
    return frame, len(frame)

def send_stp_packets(stp_info):
    seq_num = 0
    hpdu_frame, hpdu_len = create_hpdu_packet(stp_info['switch_mac'])
    tick = 0
    while True:
        for i in stp_info['interfaces']:
            send_to_link(i, hpdu_len, hpdu_frame)
        if tick % PSTP_HELLO_TIME == 0:
            ppdu_frame, ppdu_len = create_ppdu_packet(stp_info, seq_num)
            seq_num = (seq_num+ 1) % 100
            for i in stp_info['interfaces']:
                if stp_info['port_states'][i] == PORT_STATE_FORWARDING:
                    send_to_link(i, ppdu_len, ppdu_frame)
        tick += 1
        time.sleep(HPDU_INTERVAL)

def process_ppdu(data, interface, stp_info):
    try:
        config_data = data[25:56] 
        flags = config_data[0]
        rx_root_id = config_data[1:9]
        rx_root_cost = struct.unpack('!L', config_data[9:13])[0]
        rx_sender_id = config_data[13:21]
    except Exception: return
    link_cost = STP_COST_100MBPS
    new_cost_via_sender = rx_root_cost + link_cost
    current_root_id = stp_info['root_bridge_id']
    current_root_cost = stp_info['root_path_cost']
    current_bridge_id = stp_info['bridge_id']

    is_better_bpdu = False
    if rx_root_id < current_root_id:
        is_better_bpdu = True
    elif rx_root_id == current_root_id:
        if new_cost_via_sender <current_root_cost:
            is_better_bpdu = True
        elif new_cost_via_sender == current_root_cost:
            if rx_sender_id < stp_info.get('root_port_sender_id', current_bridge_id):
                is_better_bpdu = True

    if is_better_bpdu:
        stp_info['root_bridge_id'] = rx_root_id
        stp_info['root_path_cost'] = new_cost_via_sender
        stp_info['root_port'] = interface
        stp_info['root_port_sender_id'] = rx_sender_id
        recalculate_port_states(stp_info)
    else:
        recalculate_port_states(stp_info)

def recalculate_port_states(stp_info):
    port_config = stp_info['port_config']

    if stp_info['root_bridge_id'] == stp_info['bridge_id']:
        stp_info['root_path_cost'] = 0
        stp_info['root_port'] = -1
        for i in stp_info['interfaces']:
            stp_info['port_states'][i] = PORT_STATE_FORWARDING
    else:
        for i in stp_info['interfaces']:
            port_cfg = port_config[i]
            if port_cfg['type']== PORT_TYPE_TRUNK:
                if i == stp_info['root_port']:
                    stp_info['port_states'][i] = PORT_STATE_FORWARDING
                else:
                    stp_info['port_states'][i] = PORT_STATE_BLOCKING
            else:
                stp_info['port_states'][i] = PORT_STATE_FORWARDING
def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    interface_names_list = sys.argv[2:]
    num_interfaces = wrapper.init(interface_names_list)
    interfaces = range(0, num_interfaces)
    switch_mac = get_switch_mac()

    port_config = {}
    port_names = {}
    switch_priority = STP_DEFAULT_PRIORITY
    config_file = f"configs/switch{switch_id}.cfg"
    try:
        with open(config_file, 'r') as f:
            lines = f.readlines()
            if lines:
                switch_priority = int(lines[0].strip())

            temp_config_by_name = {}
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) == 2:
                    name = parts[0].strip()
                    config_val = parts[1].strip()
                    if config_val.upper() == 'T':
                        temp_config_by_name[name] = {'type': PORT_TYPE_TRUNK, 'vlan_id': 0}
                    else:
                        temp_config_by_name[name] = {'type': PORT_TYPE_ACCESS,'vlan_id': int(config_val)}
        for i in interfaces:
            name = interface_names_list[i]
            port_names[i]=name
            if name in temp_config_by_name:
                port_config[i] =temp_config_by_name[name]
            else:
                port_config[i] = {'type': PORT_TYPE_ACCESS,'vlan_id': 0}
    except Exception:
        for i in interfaces:
            port_names[i] = interface_names_list[i]
            port_config[i] = {'type': PORT_TYPE_ACCESS,'vlan_id': 0}
    bridge_id = get_bridge_id(switch_mac, switch_priority)
    stp_info = {'switch_id': switch_id,'switch_mac': switch_mac,'bridge_id': bridge_id,'interfaces': interfaces,'port_names': port_names,
                'port_config': port_config,'root_bridge_id': bridge_id,'root_path_cost': 0,'root_port': -1,
                'port_states': {i: PORT_STATE_FORWARDING for i in interfaces}}
    # Example of running a function on a separate thread.
    t = threading.Thread(target=send_stp_packets, args=(stp_info,), daemon=True)
    t.start()

    if not hasattr(main, "mac_table"):
        main.mac_table = {}
    cam_table = main.mac_table
    broadcast_mac = b'\xff' * 6

    while True:
        interface, data, length = recv_from_any_link()
        original_data = data
        original_length = length

        dest_mac_bytes, src_mac_bytes, ethertype, vlan_id_rx, vlan_tci_rx = parse_ethernet_header(data)
        if dest_mac_bytes == PPDU_DEST_MAC:
            process_ppdu(original_data, interface, stp_info)
            continue
        if (dest_mac_bytes == HPDU_DEST_MAC and ethertype == HPDU_ETHER_TYPE and original_data.endswith(HPDU_DATA)):
            continue
        if stp_info['port_states'][interface] == PORT_STATE_BLOCKING:
            continue
        data_untagged = data
        length_untagged = length
        if vlan_id_rx != -1:
            data_untagged = data[:12] + data[16:]
            length_untagged = length - 4

        if src_mac_bytes not in (broadcast_mac, switch_mac):
            cam_table[src_mac_bytes] = interface
        in_port_cfg = port_config[interface]
        vlan_id_frame = -1
        if in_port_cfg['type'] == PORT_TYPE_ACCESS:
            vlan_id_frame = in_port_cfg['vlan_id']
            if vlan_id_rx != -1:
                continue
        elif in_port_cfg['type'] == PORT_TYPE_TRUNK:
            if vlan_id_rx == -1:
                continue
            vlan_id_frame = vlan_id_rx

        if vlan_id_frame == -1:
            continue
        if dest_mac_bytes == switch_mac:
            continue

        is_broadcast = (dest_mac_bytes == broadcast_mac)
        is_multicast = (dest_mac_bytes[0] & 0x01) != 0 and not is_broadcast
        is_unicast = not (is_broadcast or is_multicast)

        out_interfaces = []
        if is_broadcast or is_multicast:
            for i in interfaces:
                if i == interface:
                    continue
                out_port_cfg = port_config[i]
                if out_port_cfg['type'] == PORT_TYPE_TRUNK:
                    out_interfaces.append(i)
                elif (out_port_cfg['type'] == PORT_TYPE_ACCESS and
                      out_port_cfg['vlan_id'] == vlan_id_frame):
                    out_interfaces.append(i)
        else:
            out_port_index = cam_table.get(dest_mac_bytes)
            if out_port_index is None:
                for i in interfaces:
                    if i == interface:
                        continue
                    out_port_cfg = port_config[i]
                    if out_port_cfg['type'] == PORT_TYPE_TRUNK:
                        out_interfaces.append(i)
                    elif (out_port_cfg['type'] == PORT_TYPE_ACCESS and out_port_cfg['vlan_id'] == vlan_id_frame): out_interfaces.append(i)
            elif out_port_index != interface:
                out_port_cfg = port_config[out_port_index]
                if out_port_cfg['type'] == PORT_TYPE_TRUNK:
                    out_interfaces.append(out_port_index)
                elif (out_port_cfg['type'] == PORT_TYPE_ACCESS and out_port_cfg['vlan_id'] == vlan_id_frame):
                    if in_port_cfg['type'] == PORT_TYPE_TRUNK:
                        expected_ext_id = calculate_mac_nibble_sum(dest_mac_bytes)
                        received_ext_id = (vlan_tci_rx >> 12) & 0xF
                        if expected_ext_id == received_ext_id:
                            out_interfaces.append(out_port_index)
                    else:
                        expected_ext_id = calculate_mac_nibble_sum(dest_mac_bytes)
                        received_ext_id = calculate_mac_nibble_sum(src_mac_bytes)
                        if expected_ext_id == received_ext_id:
                            out_interfaces.append(out_port_index)
        for out_if in out_interfaces:
            if stp_info['port_states'][out_if] == PORT_STATE_BLOCKING:
                continue
            out_port_cfg = port_config[out_if]
            if out_port_cfg['type'] == PORT_TYPE_TRUNK:
                if in_port_cfg['type'] == PORT_TYPE_ACCESS:
                    ext_id = calculate_mac_nibble_sum(src_mac_bytes)
                    vlan_tag = create_vlan_tag(ext_id, vlan_id_frame)
                    tagged_frame = data_untagged[:12] + vlan_tag + data_untagged[12:]
                    send_to_link(out_if, length_untagged + 4, tagged_frame)

                elif in_port_cfg['type'] == PORT_TYPE_TRUNK:
                    send_to_link(out_if, original_length, original_data)
            elif out_port_cfg['type'] == PORT_TYPE_ACCESS:
                send_to_link(out_if, length_untagged, data_untagged)

if __name__ == "__main__":
    main()
