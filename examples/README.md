# SignalHunter examples

Run SignalHunter with eBPF enabled for the most reliable tests:

```bash
make clean
make ebpf
sudo ./signalhunter --case-threshold 85 --verbose
```

Then in another terminal:

```bash
python3 examples/reliable_beacon.py
sudo python3 examples/high_score_trigger.py
```

`reliable_beacon.py` should trigger the eBPF connect/beacon detector.

`high_score_trigger.py` should open a case at threshold 85 because it combines raw socket, executable memory, memfd, tmp exec, scan-like connects, and local beaconing.

## Reliable reconnect heartbeat

This is the best beacon test because the connection stays open long enough for `/proc` polling and also reconnects regularly for eBPF `connect()` scoring.

```bash
python3 examples/heartbeat_reconnect.py --interval 5 --cycles 12 --hold 4
```

Run SignalHunter with score logging and an 85 case threshold:

```bash
sudo ./signalhunter --case-threshold 85 --verbose
 tail -f logs/scores.log logs/alerts.log
```
