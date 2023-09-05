# RTP Replay

Have you ever wanted to replay rtpdump files in a browser? Use this script!

1) Create an rtpdump file (see https://wiki.wireshark.org/rtpdump and https://webrtchacks.com/video_replay/)

2) Run rtp-to-webrtc as directed: https://github.com/webrtc-rs/webrtc/tree/master/examples/examples/rtp-to-webrtc

3) Run:

	python3 replayer.py <yourfile.rtpdump>

## Disclaimer

This is not an official Google product.
