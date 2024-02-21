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

## DOCA Flow Pipes

WIP.

### Net-to-Host (N2H) Datapath Flow
```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    secure_ingress{{secure_ingress}}
    secure_ingress-->ROOT
    INGR_ACL[INGR_ACL]
    RSS[[RSS]]
    drop[[drop]]

    ROOT-->|"PORT=0,
    IPV6,PSP"|PSP_DECRYPT
    PSP_DECRYPT-->|+DECR|INGR_SAMP
    INGR_SAMP-->|psp.S|INGR_ACL
    INGR_SAMP-.->|miss|INGR_ACL
    INGR_SAMP-->|MIRROR|RSS
    INGR_ACL-->|SYND,IPV6/DECAP|pf0vf0.egress
    INGR_ACL-.->|miss|drop
```

### N2H Exception Flow
```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    secure_ingress{{secure_ingress}}
    kernel{{kernel}}

    secure_ingress-->ROOT
    ROOT-->|miss|kernel
```
### Host-to-Net (H2N) Datapath Flow

```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    secure_ingress{{secure_ingress}}
    p0.secure_egress{{p0.secure_egress}}
    PSP_ENCRYPT[PSP_ENCRYPT]
    RSS[[RSS]]
    RSS2[[RSS]]

    secure_ingress-->ROOT
    ROOT-->|PORT=1|EGR_ACL
    EGR_ACL-->|"IPV4/
    +ENCAP"|EGR_SAMP
    EGR_SAMP-->|"RAND"|PSP_ENCRYPT
    EGR_SAMP-.->|miss|PSP_ENCRYPT
    EGR_SAMP-->|"MIRROR"|RSS
    PSP_ENCRYPT-->|"PSP.CRYPTO_ID/
    +ENCRYPT"|p0.secure_egress
    EGR_ACL-.->|miss|RSS2-->|"add_entry,
    Resubmit"|EGR_ACL
```

### H2N Exception packets (ARP/DHCP):
```mermaid
 %%{init:{'flowchart':{'useMaxWidth':false}}}%%
flowchart LR
    secure_ingress{{secure_ingress}}
    pf0vf0.egress{{pf0vf0.egress}}
    RSS[[RSS]]

    secure_ingress-->ROOT

    ROOT-->|"PORT=1,
    [ARP,DHCP]"|RSS
    RSS-->pf0vf0.egress
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
