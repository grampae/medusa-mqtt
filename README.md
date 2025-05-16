

<p align="center">
  <img width="460" height="460" src="https://github.com/user-attachments/assets/c35cbdc8-a71d-4fea-b27d-ca65359c33bd">
</p>

# Medusa-mqtt

Medusa-mqtt is a MQTT enabled fork of the Medusa agent, a cross-platform agent compatible with both Python 3.8.

## Installation
To install Medusa-mqtt, you'll need Mythic v3 installed on a remote computer. You can find installation instructions for Mythic at the [Mythic project page](https://github.com/its-a-feature/Mythic/).

From the Mythic install root, run the command:

`./mythic-cli install github https://github.com/grampae/medusa-mqtt.git`

Once installed, restart Mythic to build a new agent.

## Supported C2 Profiles

Currently, only one C2 profile is available to use when creating a new Medusa-mqtt agent: mqtt (both with and without AES256 HMAC encryption).

### HTTP Profile

The MQTT profile calls back to the Mythic server over messages relayed over a MQTT server.

