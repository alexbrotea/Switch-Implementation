custom_stp_proto = Proto("PSTP", "May be the best STP protocol on the planet")

local f_protocol_id = ProtoField.uint16("custom_stp.protocol_id", "Protocol Identifier", base.HEX)
local f_version = ProtoField.uint8("custom_stp.version", "Protocol Version", base.DEC)
local f_bpdu_type = ProtoField.uint8("custom_stp.bpdu_type", "PPDU Type", base.HEX)
local f_sequence = ProtoField.uint32("custom_stp.sequence", "Sequence Number", base.DEC)
local f_flags = ProtoField.uint8("custom_stp.flags", "Flags", base.HEX)
local f_root_id = ProtoField.uint64("custom_stp.root_id", "Root Bridge ID", base.HEX)
local f_path_cost = ProtoField.uint32("custom_stp.path_cost", "Root Path Cost", base.DEC)
local f_bridge_id = ProtoField.uint64("custom_stp.bridge_id", "Bridge ID", base.HEX)
local f_port_id = ProtoField.uint16("custom_stp.port_id", "Port ID", base.HEX)
local f_message_age = ProtoField.uint16("custom_stp.message_age", "Message Age", base.DEC)
local f_max_age = ProtoField.uint16("custom_stp.max_age", "Max Age", base.DEC)
local f_hello_time = ProtoField.uint16("custom_stp.hello_time", "Hello Time", base.DEC)
local f_forward_delay = ProtoField.uint16("custom_stp.forward_delay", "Forward Delay", base.DEC)

custom_stp_proto.fields = {
    f_protocol_id, f_version, f_bpdu_type, f_sequence,
    f_flags, f_root_id, f_path_cost, f_bridge_id,
    f_port_id, f_message_age, f_max_age, f_hello_time, f_forward_delay
}

function custom_stp_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "PSTP"
    
    local pkt_len = buffer:len()
    if pkt_len < 38 then
        return
    end
    
    local subtree = tree:add(custom_stp_proto, buffer(), "PSTP Data")
    
    subtree:add(f_protocol_id, buffer(0, 2))
    subtree:add(f_version, buffer(2, 1))
    subtree:add(f_bpdu_type, buffer(3, 1))
    
    local seq_num = buffer(4, 4):uint()
    subtree:add(f_sequence, buffer(4, 4)):append_text(" (Custom field)")
    
    pinfo.cols.info = string.format("PPDU [Seq: %d]", seq_num)
    
    subtree:add(f_flags, buffer(8, 1))
    subtree:add(f_root_id, buffer(9, 8))
    subtree:add(f_path_cost, buffer(17, 4))
    subtree:add(f_bridge_id, buffer(21, 8))
    subtree:add(f_port_id, buffer(29, 2))
    subtree:add(f_message_age, buffer(31, 2))
    subtree:add(f_max_age, buffer(33, 2))
    subtree:add(f_hello_time, buffer(35, 2))
    subtree:add(f_forward_delay, buffer(37, 2))
    
    return pkt_len
end

local llc_table = DissectorTable.get("llc.dsap")
llc_table:add(0x42, custom_stp_proto)
