require "bundler"
Bundler.require

require "ffi/pcap"
require "ffi/packets"

module FFI::Packets
  module Ipv6
    class Hdr < AutoStruct
      dsl_layout do
        field :v_tc_fl,            :uint32
        field :payload_length,     :uint16
        field :next,               :uint8
        field :hop_limit,          :uint8
        field :src,               [:uint8, 16]
        field :dst,               [:uint8, 16]
      end
    end
  end
end

class Airchat
  def initialize(port: 1337)
    @ip_to_host = {}
    @port = port
  end

  def run
    @pcap = FFI::Pcap::Live.new(
      device: 'awdl0',
      timeout: 1,
      handler: FFI::PCap::Handler,
      promisc: true,
    )

    @pcap.setfilter("udp and (port 1337 or port 5353)")

    while true
      packet = @pcap.next
      if packet.nil?
        sleep 0.1
      else
        io = StringIO.new(packet.body)

        eth = FFI::Packets::Eth.new(raw: io.read(FFI::Packets::Eth.size))
        ip = FFI::Packets::Ipv6::Hdr.new(raw: io.read(FFI::Packets::Ipv6::Hdr.size))
        udp = FFI::Packets::UDP.new(raw: io.read(FFI::Packets::UDP.size))

        src_ip = ip.src.to_a.map(&:chr).join # Surely there's a better way

        if udp.dport == @port
          handle_message(from: src_ip, data: io.read)
        elsif udp.dport == 5353
          handle_mdns(from: src_ip, data: io.read)
        end
      end
    end
  end

  def handle_message(from:, data:)
    if data =~ /^__AIRCHAT:/
      last_4 = from[-4..-1].unpack("H*").first
      host = @ip_to_host[from] || 'unknown'
      puts "[#{host}/#{last_4}] #{data.sub('__AIRCHAT:', '')}"
    end
  end

  def handle_mdns(from:, data:)
    packet = Resolv::DNS::Message.decode(data)

    mappings = packet.answer.select do |ans|
      # The gem doesn't seem to handle the cache-purge flag, whatever
      ans[2].class.to_s == "Resolv::DNS::Resource::Generic::Type28_Class32769"
    end

    mappings.each do |name, _, record|
      if record.data != from
        puts "Warning: record and src host mismatch"
      else
        @ip_to_host[record.data] = name.to_s.chomp(".local")
      end
    end
  end
end

Airchat.new.run

