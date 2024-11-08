# Twitchcat
A key signing service and library for network applications that interact with Twitch.

## Purpose
Software and Game Development streamers like to make applications that viewers can interact with. However, this comes with the risk of viewers doing or saying things that may violate Twitch TOS.

To reduce the risk associated with untrusted user data, Twitchcat creates a private key infrastructure using Twitch OAuth that assigned a certificate to their Twitch username. This allows for non-repudiation of messages sent to a streamers service. 

## Flow
Key Signing Service 
     <------------------- Lowlevel.Tv <-------- Twitch OAuth

Application (c, rust, go) <----- Reverse Proxy <----- twitch.crt
