# Can vpnctl become a client for an open VPN network?

The idea was: make this repository public, and people just join an open source
VPN network through it. This document is about whether such a network exists to
join, and what it would cost you personally to plug into one.

Short answer: networks like that exist, several of them, and joining as a
**user** is easy. The problem is the other half of the sentence. An open
network only works because somebody's connection carries strangers' traffic out
to the internet, and the projects that run these networks are explicit that the
person who does that carries the legal risk, not the project.

## First, a distinction that matters

Two different things get called "open source VPN", and conflating them is how
this idea gets planned badly.

**Open source VPN software.** WireGuard, OpenVPN, Tailscale and Headscale.
The code is open. There is no shared network: you run it, you are the only one
on it, and the exit point is a machine you rent. This is what `vpnctl` already
does, and it does it well.

**An open network of relays.** Tor, I2P, Lokinet, Yggdrasil, Mysterium,
Sentinel, Orchid. Here the point is that other people's machines carry your
traffic and yours carries theirs. That is the thing described in the original
idea, and it is a different product with a different risk profile.

## The networks that actually exist

**Tor** is the mature one. Free, no token, enormous relay population, and the
only one of these with two decades of adversarial scrutiny. It is not a VPN and
does not try to be: it is slow by design, and a lot of services block its exits.

**I2P** and **Yggdrasil** are overlay networks for reaching things inside the
network. Neither is aimed at "route my normal browsing out to the clear web",
which is what a VPN means to most people.

**Lokinet**, **Mysterium**, **Sentinel** and **Orchid** are the crypto funded
dVPNs. They do route ordinary traffic. Mysterium's consumer app routes through
a peer to peer network of thousands of nodes run by ordinary people on home
machines. Orchid differs by sourcing exits from commercial VPN providers and
hosting companies rather than from users, which is a meaningfully safer design
for the operator, because the operator is a company that chose that business.

## The part that decides this

Mysterium's own exit node terms are unambiguous. Quoting them directly:

> Although we strongly believe that you should not be liable for the traffic
> which passes through your Node, you accept, agree and fully understand that
> we cannot guarantee that no illegal or criminal traffic passes in or through
> the Network and that you will never face any legal liability.

And the indemnity runs the opposite way to the one you would want:

> You agree to defend, indemnify and hold harmless us, our affiliates and their
> respective directors, officers, employees and agents from and against all
> claims and expenses, including attorneys' fees, arising out of the use of the
> Network by you or your account.

Source: [TERMS_EXIT_NODE.md](https://github.com/mysteriumnetwork/node/blob/master/TERMS_EXIT_NODE.md).

Read that twice. You accept the risk, and you additionally agree to cover the
company's legal costs. Independent reviews make the same point: running a node
means the project's terms put the first line legal risk on you for whatever
strangers push through your address
([State of Surveillance](https://stateofsurveillance.org/resources/mysterium-vpn/)).
The dVPN Alliance's own guidance for exit node operators exists precisely
because this is a known hazard
([dvpnalliance.org](https://dvpnalliance.org/exit-node/)).

What that looks like in practice is abuse complaints to your ISP, your address
appearing in other people's logs during investigations, and in some
jurisdictions direct liability for what crossed your line. Germany is the
usual cited example, where the line holder has been held responsible for
infringement originating from their connection
([vpnpro overview](https://vpnpro.com/blog/decentralized-p2p-blockchain-vpn-projects/)).

I could not find a Georgia specific statutory answer on exit node operator
liability, and I am not going to invent one. Treat that as unknown rather than
as absence of risk. Georgia's data and communications law is not the same as
Germany's, but nothing found here supports assuming it is safer.

## What this means for vpnctl

**Do not turn vpnctl into an exit node.** Not because the code is hard, it is
not, but because publishing a repository that makes it a single command for
strangers to start carrying other people's traffic means shipping that
liability to every person who runs it. The project would be handing out a legal
exposure it cannot explain or cover.

**Being a client of one is a reasonable feature.** Adding a provider that
connects to an existing network is a small piece of work and carries none of
the same risk. `vpnctl` already has a provider abstraction in
`src/vpnctl/providers/`, and the existing Cloudflare WARP and WireGuard paths
show the shape. A Tor or Mysterium client provider would slot in there.

**The honest positioning is what it already is.** vpnctl manages your own
tunnels, and its best feature is the one command Tailscale exit node on a VPS
you control. That is not a lesser version of the open network idea, it is the
version where the exit is a machine you rent, in a jurisdiction you chose, and
the only traffic on it is yours. For most people that is what they actually
wanted from a VPN.

If the goal is to contribute capacity to a public network, the mature answer is
to run a Tor **middle relay**, which forwards traffic between relays and never
exits to the clear internet, so it carries none of the exit operator risk. That
is a genuinely useful contribution and it is a different thing from what
vpnctl does.

---

Researched 2026-09-14. This is research and not legal advice. Terms and law
change, and the Mysterium terms quoted above should be re-read before acting
on any of this.
