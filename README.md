<!---
/*
 * Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */
--->
# User-Space PSP Application README

## Sequence of Events

In this sequence, two hosts, H1 and H2, are running tenant VM workloads V1 and V2, respectively, as well as the PSP application.

The sequence begins with the workload V1 on host H1 attempting to send a packet to workload V2 on host H2.

```mermaid
 %%{init: { 'sequence': { 'useMaxWidth':false, "mirrorActors":false} } }%%
sequenceDiagram
    autonumber
    participant V1
    participant H1
    participant H2
    participant H2

    note over V1,V2: Slow Path
    V1 ->> H1: packet P1 to V2
    H1 ->> H1: lookup flow rule (miss)
    activate H1
    H1 ->> H1: store the miss packet P1
    H1 ->> H1: derive key K[H1]
    activate H2
    H1 ->> H2: rpc:NewTunnelRequest(K[H1])
    H2 ->> H2: derive key K[H2]
    H2 ->> H2: program flow to H1.V1 with K[H1]
    H2 ->> H1: rpc:NewTunnelResponse(K[H2])
    deactivate H2
    H1 ->> H1: program flow to H2.V2 with K[H2]
    H1 ->> H1: resubmit packet P1
    deactivate H1
    H1 ->> H2: encrypted packet E(K[H2], P1)
    H2 ->> V2: packet P1

    note over V1,V2: Fast Path
    par
        V1 ->> H1: packet PN to V2
        H1 ->> H1: lookup flow rule (match)
        H1 ->> H2: encrypted packet E(K[H2], PN)
        H2 ->> V2: packet PN
    and
        V2 ->> H2: packet PN to V1
        H2 ->> H2: lookup flow rule (match)
        H2 ->> H1: encrypted packet E(K[H1], PN)
        H1 ->> V1: packet PN
    end
```

## DOCA Flow Pipes: Host-to-Net (H2N) Datapath

### H2N Flow (No Sampling, Static Tunnel Assignment)

```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    ingress{{ingress}}
    p0{{p0}}
    EGR_ACL["EGR_ACL
    M:ipv4.dst
    A:encap(),
    encrypt()"]

    ingress-->ROOT
    ROOT-->|"M:port=1,
    ipv4"|EGR_ACL
    EGR_ACL-->p0
    EGR_ACL-.->|miss|DROP
```

### H2N Datapath Flow (Sampling Enabled)

```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    ingress{{ingress}}
    p0{{p0}}
    EGR_ACL["EGR_ACL
    M:ipv4.dst
    A:encap(),
    pkt_meta=crypto_id"]
    EGR_SAMP["EGR_SAMP
    M:rand()=1
    MM:0xffff
    A:psp.S=1"]
    PSP_ENCRYPT["PSP_ENCRYPT
    M:pkt_meta
    A:encrypt()"]
    RSS[[RSS]]
    RSS2[["RSS Miss Handler
    - RPC()
    - add_entry()
    "]]

    ingress-->ROOT
    ROOT-->|"M:port=1,
    ipv4"|EGR_ACL
    EGR_ACL-->EGR_SAMP
    EGR_SAMP-->PSP_ENCRYPT
    EGR_SAMP-.->|miss|PSP_ENCRYPT
    EGR_SAMP-->|"mirror"|RSS
    PSP_ENCRYPT-->p0
    EGR_ACL-.->|miss|RSS2-->|resubmit|EGR_ACL
```

### H2N Exception packets (ARP/DHCP):
```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    ingress{{ingress}}
    pf0vf0{{pf0vf0}}
    RSS[["RSS
    - generate_reply()
    "]]

    ingress-->ROOT

    ROOT-->|"M:port=1,
    [arp,dhcp]"|RSS
    RSS-->pf0vf0
```

## DOCA Flow Pipes: Net-to-Host (N2H) Datapath

### N2H Datapath Flow (No Sampling)

```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    ingress{{ingress}}
    pf0vf0{{pf0vf0}}
    ingress-->ROOT
    INGR_ACL[INGR_ACL]
    drop[[drop]]
    PSP_DECRYPT["PSP_DECRYPT
    A:decrypt()"]
    INGR_ACL["INGR_ACL
    M:synd,ipv6
    A:decap()"]
    SYND_STATS["SYND_STATS
    M:psp.synd"]

    ROOT-->|"M:port=0,
    ipv6/psp"|PSP_DECRYPT
    PSP_DECRYPT-->INGR_ACL
    INGR_ACL--->pf0vf0
    INGR_ACL-.->|miss|SYND_STATS
    SYND_STATS-->drop
```

### n2H Datapath Flow (Sampling Enabled)

```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    ingress{{ingress}}
    pf0vf0{{pf0vf0}}
    ingress-->ROOT
    INGR_ACL[INGR_ACL]
    RSS[[RSS]]
    drop[[drop]]
    PSP_DECRYPT["PSP_DECRYPT
    A:decrypt()"]
    INGR_SAMP["INGR_SAMP
    M:psp.S=1"]
    INGR_ACL["INGR_ACL
    M:synd,ipv6
    A:decap()"]
    SYND_STATS["SYND_STATS
    M:psp.synd"]

    ROOT-->|"M:port=0,
    ipv6/psp"|PSP_DECRYPT
    PSP_DECRYPT-->INGR_SAMP
    INGR_SAMP-->INGR_ACL
    INGR_SAMP-.->|miss|INGR_ACL
    INGR_SAMP-->|mirror|RSS
    INGR_ACL--->pf0vf0
    INGR_ACL-.->|miss|SYND_STATS
    SYND_STATS-->drop
```

### N2H Exception Flow

The `Isolated Mode` causes unmatched packets at the root pipe to be forwarded to the kernel.

```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    ingress{{ingress}}
    kernel{{kernel}}

    ingress-->ROOT
    ROOT-->|miss|kernel
```

### Pipe Entry Scale Factors

For 'N' peers.

|Pipe|Entries|Dynamic|Notes|
|----|----|----|----|
|ROOT|3|No|Classification of Flows
|PSP_DECRYPT|1|No|One master key supports all N peers
|PSP_ENCRYPT|N|No|Maps meta->crypto_id; never changes
|INGR_ACL|N|Yes|
|EGR_ACL|N|Yes|Maps each dst IP to meta
