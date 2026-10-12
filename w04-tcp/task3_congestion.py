#!/usr/bin/env python3
"""Week 4 · Task 3 — Beat the fixed window.

Textbook §3.7.

`FixedWindow` is a sender that never adapts. It picks a window and keeps it,
forever, no matter what the network says back. It is not a strawman: it is what
you get if you skip congestion control entirely, and it was the internet's
actual failure mode in October 1986.

Write `YourControl` and beat it on the harness:

    python3 bench.py
    python3 bench.py --yours

The interface is two events and one number:

    .window        how many packets you are willing to have in flight
    .on_ack()      one packet made it there and back
    .on_loss()     a packet was dropped, or timed out waiting for its ACK

That is all the information a real TCP sender has. It cannot see the queue,
it cannot see the link rate, and neither can you. You infer them from these
two events, which is the entire idea of §3.7.
"""


class FixedWindow:
    """Send 64 packets at a time and never listen."""

    def __init__(self):
        self.window = 64

    def on_ack(self):
        pass

    def on_loss(self):
        pass


class YourControl:
    """Your congestion control.

    Things worth knowing before you start:

    * The link drains one packet per slot and the round trip is 20 slots, so
      the pipe holds about 20 packets. Above that you are only filling a queue.
    * The queue is 10 packets deep and drops from the tail. Filling it does not
      make you faster - it makes you slower, and everybody behind you too.
    * Cutting hard on every loss costs you throughput. Not cutting costs you
      correctness. §3.7 is the argument about where between those to sit.
    * You are allowed to grow differently before and after your first loss.
      That distinction has a name in the textbook.
    """

    BETA = 0.7      # multiplicative decrease: keep 70% (CUBIC's beta), not Reno's 50%

    def __init__(self):
        self.window = 1.0
        self.ssthresh = float("inf")    # slow start until the network says stop
        self.acks_since_cut = 0

    def on_ack(self):
        self.acks_since_cut += 1
        if self.window < self.ssthresh:
            self.window += 1                    # slow start: doubles every RTT
        else:
            self.window += 1 / self.window      # congestion avoidance: +1 per RTT

    def on_loss(self):
        # One tail-drop burst times out as many separate losses. React once per
        # window of data, like Reno's fast recovery, instead of once per packet.
        if self.acks_since_cut < self.window and self.ssthresh != float("inf"):
            return
        self.ssthresh = max(2.0, self.window * self.BETA)
        self.window = self.ssthresh
        self.acks_since_cut = 0
