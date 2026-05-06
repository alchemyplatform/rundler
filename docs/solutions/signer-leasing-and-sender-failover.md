---
title: Signer Leasing and Sender Failover
date: 2026-05-06
tags:
  - solutions
  - builder
  - signer
area: builder
---

# Signer Leasing and Sender Failover

## Problem

Changes to bundle sending can create nonce collisions, leaked signer leases, or
cancellations routed to the wrong submission path.

## Root Cause

The builder pairs workers with signer leases. KMS signing can use Redis locks to
avoid multiple processes using the same key. Transaction sender fallback tracks
whether the last transaction used the fallback so cancellation goes to the same
sender that submitted the transaction.

## Solution

Return signer leases on all terminal paths, keep KMS lock IDs scoped by
`chain_id:key_id`, and preserve `FallbackTransactionSender` cancellation
routing. Treat `SenderUnavailable` as the failover signal; do not collapse all
sender errors into outage errors.

