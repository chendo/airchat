#!/usr/bin/env ruby

# AirChat lets you chat to other people nearby who are
# also running AirChat by (ab)using the AirDrop interface.
#
#

# Usage: [sudo] ./airchat.rb

require "readline"
require "securerandom"
require "json"
require "socket"
require "open3"
require "fileutils"
require "timeout"
require "digest/sha1"

# Airchat protocol
# JSON
# from: 'nick'
# id: uuid
# event: [join/leave/msg/ack]
# data: {msg: }

Thread.abort_on_exception = true

def debug_log(msg)
  if ENV['DEBUG']
    eputs msg
  end
end

module ANSIColor
  module_function

  # from Paint gem
  def rgb(red, green, blue)
    gray_possible = true
    sep = 42.5

    while gray_possible
      if red < sep || green < sep || blue < sep
        gray = red < sep && green < sep && blue < sep
        gray_possible = false
      end
      sep += 42.5
    end

    if gray
      "\033[38;5;#{ 232 + ((red.to_f + green.to_f + blue.to_f)/33).round }m"
    else # rgb
      "\033[38;5;#{ [16, *[red, green, blue].zip([36, 6, 1]).map{ |color, mod|
        (6 * (color.to_f / 256)).to_i * mod
      }].inject(:+) }m"
    end
  end

  COLOURS = {
    red: [205, 0, 0],
    yellow: [205,205,0],
    blue: [0,0,238],
    green: [0, 205, 0],
    orange: [205, 120, 0],
    cyan:    [0,205,205],
    white: [229, 229, 229],
  }
  NOTHING = "\033[0m".freeze

  def paint(str, color)
    color = COLOURS[color] || color
    "#{rgb(*color)}#{str}#{NOTHING}"
  end
end

class String
  def c(color)
    ANSIColor.paint(self, color)
  end
end

def eputs(str)
  $stderr.puts ANSIColor.paint(str, :red)
end

class Airchat
  RELIABILITY_FACTOR = 1 # lol
  PING_INTERVAL = 10
  def initialize(port: 1337, preamble: '__AIRCHAT:')
    @ip_to_host = {}
    @port = port
    @preamble = preamble
    @seen_messages = []
    @socket = UDPSocket.new(Socket::AF_INET6)
    @socket.connect('ff02::fb%awdl0', @port)
    @output_mutex = Mutex.new
    @last_awdl_activity = Time.at(0)
    @ip_last_seen = {}
    @ip_nick = {}
    @ip_timed_out = {}
  end

  def check_permissions
    Dir["/dev/bpf*"].each do |f|
      FileUtils.touch(f)
    end
  rescue Errno::EPERM
    eputs "AirChat does not have permissions to access the AirDrop interface."
    eputs "Please run: `sudo chgrp staff /dev/bpf* && sudo chmod g+rw /dev/bpf*`"
    eputs "re-run AirChat as root with `sudo ./airchat.rb`"
    exit 1
  end

  def check_airdrop
    print "Checking if AirDrop is running.".c(:yellow)
    begin
      Timeout.timeout(5) do
        while Time.now - @last_awdl_activity > 5
          print ".".c(:yellow)
          sleep 1
        end
      end
    rescue Timeout::Error
      print "\n"
      puts "AirDrop not running, opening AirDrop window...".c(:orange)
      open_airdrop_window

      begin
        print "Checking if AirDrop is working.".c(:yellow)
        Timeout.timeout(5) do
          while Time.now - @last_awdl_activity > 5
            print ".".c(:yellow)
            sleep 1
          end
        end
      rescue Timeout::Error
        exit 1
      end
    end
    puts " OK".c(:green)
  end

  def airdrop_monitor
    while true
      if Time.now - @last_awdl_activity > 60
        status_output("No AirDrop activity detected, opening AirDrop window...")
        open_airdrop_window
      end
      sleep 5
    end
  end

  def prompt_text
    "\r[#{@nick.c(:cyan)}] "
  end

  def write(msg)
    @socket.write("#{@preamble}#{msg.to_json}")
  end

  def send_msg(type, **args)
    msg = Message.send(type, **{from: @nick}.merge(args))
    RELIABILITY_FACTOR.times { write(msg) }
  end

  def run
    Thread.new do
      listen
    end

    Thread.new do
      airdrop_activity_monitor
    end

    puts "Welcome to AirChat.".c(:green)
    puts "-------------------".c(:green)

    check_permissions
    check_airdrop

    Thread.new do
      airdrop_monitor
    end

    print "Enter your nickname: ".c(:cyan)

    @nick = gets.match(/(\w{1,32})/)[1]
    if @nick.length == 0
      @nick = "Guest#{rand(10000)}"
    end

    at_exit do
      send_msg(:leave)
    end

    Thread.new do
      pinger
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
        elsif line =~ /\/who/
          status_output("Users:")
          @ip_last_seen.each do |ip, time|
            nick = @ip_nick[ip] || "???"

            status_output("   #{nick}@#{ip} - seen #{(Time.now - time).round}s ago")
          end
        else
          send_msg(:msg, msg: line)
        end
      end
    end
  end

  def pinger
    while true
      sleep PING_INTERVAL
      send_msg(:ping)
      lost = []
      @ip_last_seen.each do |ip, time|
        if Time.now - time > (PING_INTERVAL * 3) && @ip_timed_out[ip].nil?
          lost << ip
          @ip_timed_out[ip] = true
        end
      end
      lost.each do |ip|
        nick = @ip_nick[ip] || "???"
        status_output("#{nick}@#{suffix(ip)} has timed out")
      end
    end
  end

  def listen
    ip = nil
    len = 0
    output_buffer = StringIO.new
    buffer = StringIO.new

    Open3.popen3("tcpdump -n --immediate-mode -l -x -i awdl0 udp and port #{@port}") do |i, o, e, t|
      o.each do |line|
        if line =~ /IP6 ([0-9a-f:.]+).+ length (\d+)/
          ip = $1
          len = $2.to_i # This is hex
        elsif line =~ /0x(\d{4}):  ([0-9a-f ]+)/
          if $1.to_i >= 30 # We only want the UDP data, which starts at 0x0030
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

  def open_airdrop_window
    Open3.popen3("osascript -") do |i, o, e, t|
      i << <<-SCRIPT
      tell application "Finder"
          activate
          tell application "System Events" to keystroke "R" using {command down, shift down}
          set visible of application process "Finder" to false
      end tell
      SCRIPT
    end
  end

  def airdrop_activity_monitor
    Open3.popen3("tcpdump -n --immediate-mode -l -x -i awdl0 not port #{@port}") do |i, o, e, t|
      o.each do
        @last_awdl_activity = Time.now
      end
    end
  end

  def output(line)
    puts "\r[#{Time.now.strftime("%H:%M:%S")}] #{line}"
  end

  def status_output(line)
    output("* #{line}".c(:orange))
  end

  def suffix(ip)
    ip.split(':')[-2..-1].join(':')
  end

  def handle_message(from:, data:)
    return if @nick.nil? # We're not 'connected'

    if data =~ /^#{@preamble}/
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

      nick = msg.from
      cnick = colorise_nick(msg.from, from)
      host = from

      @ip_nick[from] = nick
      @ip_last_seen[from] = Time.now

      case msg.event
      when 'join'
        status_output "#{cnick} has joined from #{host}"
      when 'leave'
        status_output "#{cnick} has left (#{host})"
      when 'msg'
        output "[#{cnick}] #{msg.data}"
      when 'nick'
        status_output "#{cnick} changed nick to #{msg.data}"
      when 'ping'
        send_msg(:pong)
      end
      print prompt_text
    end
  end

  def colorise_nick(nick, host)
    nick.c(Digest::SHA1.digest("hello")[0...3].chars.map(&:ord))
  end

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

    def self.ping(from:, data: nil)
      create(from: from, event: 'ping')
    end

    def self.pong(from:, data: nil)
      create(from: from, event: 'pong')
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

Airchat.new.run

