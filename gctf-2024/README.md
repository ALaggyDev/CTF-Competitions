# Google CTF 2024

Our team (`ssi`) managed to score 8 flags (out of 30) and reached 36th place. Most of the work is done by Jorian Woltjer (https://jorianwoltjer.com/).

I managed to solve `pwn_encrypted_runner` in the event. I solved `misc_hwsim` 3 hours after the end of the event.

`pwn_encrypted_runner` is fine. I got the gist of it pretty quickly, but struggled to write a working exploit for a while. See my writeup on `pwn_encrypted_runner/README.md`.

`misc_hwsim` is stupid. You need to write a working counter, edge detectors, etc in only NAND gates. Timing is extremely hard (you don't have 1-tick delay that don't flip signal, or 0-tick NOT gate, etc.). You also need to not create any loop that runs forever. Pain.

Easy challenges are already done when I started solving CTF challenges. I tried solving some difficult challenges and couldn't find any exploits in it :(.
