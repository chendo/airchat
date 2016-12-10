require "readline"
require "securerandom"
require "json"

# Airchat protocol
# JSON
# from: 'nick'
# id: uuid
# event: [join/leave/msg/ack]
# data: {msg: }

Thread.abort_on_exception = true

def debug_log(msg)
  if ENV['DEBUG']
    $stderr.puts msg
  end
end

class Airchat
  class Message < Struct.new(:id, :from, :event, :data)
    def self.parse(json)
      data = JSON.parse(json)
      id, from, event, data = [:id, :from, :event, :data].map do |key|
        data.fetch(key.to_s)
      end
      new(id, from, event, data)
    rescue => ex
      debug_log(ex)
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
  RELIABILITY_FACTOR = 1 # lol
  def initialize(port: 1337, preamble: '__AIRCHAT:')
    @ip_to_host = {}
    @port = port
    @preamble = preamble
    @seen_messages = []
    @socket = UDPSocket.new(Socket::AF_INET6)
    @socket.connect('ff02::fb%awdl0', @port)
    @output_mutex = Mutex.new
  end

  def prompt_text
    "\r[#{@nick}] "
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

    line = nil
    while true
      @output_mutex.synchronize do
        line = Readline.readline(prompt_text).chomp
        print "\033[1A\033[K"
      end

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
    ip = nil
    len = 0
    output_buffer = StringIO.new
    buffer = StringIO.new

    IO.popen('tcpdump -n --immediate-mode -l -x -i awdl0 udp and port 1337') do |io|
      io.each do |line|
        if line =~ /IP6 ([0-9a-f:]+).+ length (\d+)/
          ip = $1
          len = $2.to_i
        elsif line =~ /0x(\d{4}):  ([0-9a-f ]+)/
          if $1.to_i >= 30 # lol
            buffer << [$2.gsub(' ', '')].pack("H*")
            if buffer.length == len
              handle_message(from: ip, data: buffer.string)
              buffer = StringIO.new
            end
          end
        end
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
      suffix = from.split(':')[-2..-1].join(':')

      json = data.sub(@preamble, '')
      msg = Message.parse(json)

      return if msg.nil?

      if @seen_messages.include?(msg.id)
        return
      end

      @seen_messages << msg.id
      while @seen_messages.count > 100
        @seen_messages.delete_at(0)
      end

      nick = msg.from || @ip_to_host[from] || 'unknown'
      from = "#{nick}@#{suffix}"
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

