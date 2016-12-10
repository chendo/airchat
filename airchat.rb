require "bundler"
Bundler.require

require "ffi/pcap"
require "ffi/packets"
require "readline"
require "securerandom"
require "json"

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

# Airchat protocol
# JSON
# from: 'nick'
# id: uuid
# event: [join/leave/msg/ack]
# data: {msg: }

Thread.abort_on_exception = true

class Airchat
  class Message < Struct.new(:id, :from, :event, :data)
    def self.parse(json)
      data = JSON.parse(json)
      id, from, event, data = [:id, :from, :event, :data].map do |key|
        data.fetch(key.to_s)
      end
      new(id, from, event, data)
    end

    def self.create(from:, event:, data: nil)
      new(SecureRandom.uuid, from, event, data)
    end

    def self.msg(from:, msg:)
      create(from: from, event: 'msg', data: msg)
    end

    def self.nick(from:, new_nick:)
      create(from: from, event: 'nick', data: new_nick)
    end

    def self.join(from:, data: nil)
      create(from: from, event: 'join')
    end

    def self.leave(from:, data: nil)
      create(from: from, event: 'leave')
    end

    def to_json
      JSON.dump({
        id: id,
        from: from,
        event: event,
        data: data
      })
    end
  end
end

class Airchat
  RELIABILITY_FACTOR = 3 # lol
  def initialize(port: 1337, preamble: '__AIRCHAT:')
    @ip_to_host = {}
    @port = port
    @preamble = preamble
    @seen_messages = []
    @socket = UDPSocket.new(Socket::AF_INET6)
    @socket.connect('ff02::fb%awdl0', @port)
  end

  def prompt_text
    "[#{@nick}] "
  end

  def write(msg)
    @socket.write("#{@preamble}#{msg.to_json}")
  end

  def send_msg(type, **args)
    msg = Message.send(type, **{from: @nick}.merge(args))
    RELIABILITY_FACTOR.times { write(msg) }
  end

  def run
    print "Enter your nickname: "
    @nick = gets.match(/(\w{1,32})/)[1]
    if @nick.length == 0
      @nick = "Guest#{rand(10000)}"
    end
    at_exit do
      send_msg(:leave)
    end

    listen_thr = Thread.new do
      listen
    end

    send_msg(:join)

    while true
      line = Readline.readline(prompt_text).chomp
      print "\033[1A\033[K"

      if line.length > 0
        if line =~ /\/nick (\w{1,32})/
          send_msg(:nick, new_nick: $1)
          @nick = $1
        else
          send_msg(:msg, msg: line)
        end
      end
    end
  end

  def listen
    @pcap = FFI::Pcap::Live.new(
      device: 'awdl0',
      timeout: 1,
      handler: FFI::PCap::Handler,
      promisc: true,
    )

    @pcap.setfilter("udp and port #{@port}")

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

        handle_message(from: src_ip, data: io.read)
      end
    end
  end

  def output(line)
    puts "\r[#{Time.now.strftime("%H:%M:%S")}] #{line}"
  end

  def status_output(line)
    output("* #{line}")
  end

  def handle_message(from:, data:)
    if data =~ /^#{@preamble}/
      last_4 = from[-4..-1].unpack("H*").first

      json = data.sub(@preamble, '')
      msg = Message.parse(json)

      if @seen_messages.include?(msg.id)
        return
      end

      @seen_messages << msg.id
      while @seen_messages.count > 100
        @seen_messages.delete_at(0)
      end

      nick = msg.from || @ip_to_host[from] || 'unknown'
      from = "#{nick}@#{last_4}"
      case msg.event
      when 'join'
        status_output "#{from} has joined"
      when 'leave'
        status_output "#{from} has left"
      when 'msg'
        output "[#{from}] #{msg.data}"
      when 'nick'
        status_output "#{from} changed nick to #{msg.data}"
      end
      print prompt_text
    end
  end
end

Airchat.new.run

