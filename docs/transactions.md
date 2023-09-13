## Bundle Transaction Submission

There are three types of senders that we have implemented to propagate bundles on to the chain. 

- `RawTransactionSender`
  - This sender will send the bundle as an `eth_sendRawTransaction`, so each of the transactions will need to be signed 
    before sending the bundle to the node url provided. 
- `ConditionalTransactionSender` 
  - This sender will send the bundle as an `eth_sendRawTransactionConditional`, so each of the transactions will need to
    be signed before sending the bundle to the node url provided.
- `FlashbotsTransactionSender`
  - This sender will send the bundle as an `eth_sendBundle`, so each of the transactions will need to be signed before
    sending the bundle to the flashbots protect relay url. 

When a bundle is submitted, we wait 2 blocks to see if the transaction has been mined. If the transaction has not 
been mined within `BUILDER_MAX_BLOCKS_TO_WAIT_FOR_MINE` blocks, we increase the gas fees `BUILDER_REPLACEMENT_FEE_PERCENT_INCREASE`
percent. We repeat this process until the transaction either lands on chain or we increase the fee over `BUILDER_REPLACEMENT_FEE_PERCENT_INCREASE`  
times and in that case the transaction will be set as stalled in the `SendBundleResult::StalledAtMaxFeeIncreases` type.




