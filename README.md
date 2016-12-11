# AirChat

AirChat is a zero-dependency* P2P CLI chat tool that (ab)uses the AirDrop interface to
allow chatting across WiFi networks (or no WiFi network).

A RailsCamp AU 20 project.

## Features

* Chat to other AirChat users in proximity without being on the same network
* Self-contained - no gems, nothing else to download/install
* Automatically keeps AirDrop active
* `/nick`, `/who`, `/me`, `/quit`
* User colours tied to their IPv6 address

## Requirements

* OS X 10.9+ with working AirDrop
* Ruby 2.0 or higher (comes with 10.9+)
* tcpdump (comes with 10.9+)

## Usage

```
# Get it
curl -L https://github.com/chendo/airchat/raw/master/airchat.rb > airchat.rb && chmod +x airchat.rb
# or get someone to AirDrop it to you, etc.

# AirChat requires raw access to the /dev/bpf* interface.
# Run using sudo
sudo ./airchat.rb
# OR
# Give permission to /dev/bpf*
sudo chgrp staff /dev/bpf* && sudo chmod g+rw /dev/bpf*  # These permissions will reset on reboot
./airchat.rb
```

## How does it work?

AirChat uses the `awdl0` interface to talk to other machines with AirDrop active.
However, OS X restricts binding to this interface, and non-AirDrop network traffic is rejected
with `ICMP Port Unreachable`. AirChat gets around this by using `tcpdump` to receive UDP data,
as OS X doesn't stop you from sending packets through that interface.

AirChat broadcasts JSON-encoded messages in UDP to `ff02::fb` on port `1337`.

## Caveats/TODO

* Messages are transmitted in plain text.
* No direct messaging
* One channel only (you can specify a different port by modifying the source)
* Message delivery is not guaranteed

## License

MIT.
