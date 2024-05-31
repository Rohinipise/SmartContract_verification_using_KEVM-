ERC20-ish Verification
======================

```k
requires "edsl.md"
requires "optimizations.md"
requires "lemmas/lemmas.k"
```

Solidity Code
-------------

File [`ERC20.sol`](ERC20.sol) contains some code snippets we want to verify the functional correctness of.
Call `kevm solc-to-k ERC20.sol ERC20 > erc20-bin-runtime.k`, to generate the helper K files.

Verification Module
-------------------

Helper module for verification tasks.

- Add any lemmas needed for our proofs.
- Import a large body of existing lemmas from KEVM.

```k
requires "erc20-bin-runtime.k"

module VERIFICATION
    imports EDSL
    imports LEMMAS
    imports EVM-OPTIMIZATIONS
    imports ERC20-VERIFICATION

    syntax Step ::= ByteArray | Int
    syntax KItem ::= runLemma ( Step ) | doneLemma ( Step )
 // -------------------------------------------------------
    rule <k> runLemma(S) => doneLemma(S) ... </k>

 // decimals lemmas
 // ---------------

    rule         255 &Int X <Int 256 => true requires 0 <=Int X [simplification, smt-lemma]
    rule 0 <=Int 255 &Int X          => true requires 0 <=Int X [simplification, smt-lemma]

endmodule
```

K Specifications
----------------

Formal specifications (using KEVM) of the correctness properties for our Solidity code.

```k
module ERC20-SPEC
    imports VERIFICATION
```

### Calling getAdmin() works

```k
    claim [getAdmin.success]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                      </callStack>
          <program>   #binRuntime(ERC20)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>

          <id>         ACCTID      => ?_ </id>
          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>

          <callData>   ERC20.getAdmin()                 </callData>
          <k>          #execute   => #halt ...          </k>
          <output>     .ByteArray => #buf(32, ADMIN) </output>
          <statusCode> _          => EVMC_SUCCESS     </statusCode>

          <account>
            <acctID> ACCTID </acctID>
            <storage> ACCT_STORAGE </storage>
            ...
          </account>
         

       requires ADMIN_KEY ==Int #loc(ERC20.admin_id)
       andBool ADMIN ==Int #lookup(ACCT_STORAGE,ADMIN_KEY)
       andBool #rangeAddress(ADMIN)
       andBool ADMIN =/=Int 0

```

### Calling Approve works

- Everything from `<mode>` to `<substate>` is boilerplate.
- We are setting `<callData>` to `approve(SPENDER, AMOUNT)`.
- We ask the prover to show that in all cases, we will end in `EVMC_SUCCESS` when `SENDER` or `OWNER` is not `address(0)`, and that we will end in `EVMC_REVERT` (rollback) when either one of them is.
- We take the OWNER from the `<caller>` cell, which is the `msg.sender`.
- The `<output>` should be `#buf(32, bool2Word(True))` if the function does not revert.
- The storage locations for Allowance should be updated accordingly.

```k
    claim [approve.success]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                      </callStack>
          <program>   #binRuntime(ERC20)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>
          <static>    false                                      </static>

          <id>         ACCTID      => ?_ </id>
          <caller>     OWNER       => ?_ </caller>
          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>
          <substate> _             => ?_ </substate>

          <callData>   ERC20.approve(SPENDER, AMOUNT) </callData>
          <k>          #execute   => #halt ...        </k>
          <output>     .ByteArray => #buf(32, 1)      </output>
          <statusCode> _          => EVMC_SUCCESS     </statusCode>

          <account>
            <acctID> ACCTID </acctID>
            <storage> ACCT_STORAGE => ACCT_STORAGE [ ALLOWANCE_KEY <- AMOUNT ] </storage>
            ...
          </account>

       requires ALLOWANCE_KEY ==Int #loc(ERC20._allowances[OWNER][SPENDER])
        andBool #rangeAddress(OWNER)
        andBool #rangeAddress(SPENDER)
        andBool #rangeUInt(256, AMOUNT)
        andBool OWNER =/=Int 0
        andBool SPENDER =/=Int 0
```

```k
    claim [approve.revert]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                      </callStack>
          <program>   #binRuntime(ERC20)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>
          <static>    false                                      </static>

          <id>         ACCTID      => ?_ </id>
          <caller>     OWNER       => ?_ </caller>
          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>
          <substate> _             => ?_ </substate>

          <callData>   ERC20.approve(SPENDER, AMOUNT) </callData>
          <k>          #execute   => #halt ...        </k>
          <output>     _          => ?_               </output>
          <statusCode> _          => EVMC_REVERT      </statusCode>

          <account>
            <acctID> ACCTID </acctID>
            <storage> _ACCT_STORAGE </storage>
            ...
          </account>

       requires #rangeAddress(OWNER)
        andBool #rangeAddress(SPENDER)
        andBool #rangeUInt(256, AMOUNT)
        andBool (OWNER ==Int 0 orBool SPENDER ==Int 0)
```

### Add Positive Case

- `<callData>` says we are calling `add(X, Y)`.
- `<output>` says we expect the function to return `X +Int Y` (addition did not overflow).
- `<statusCode>` says we expect the function to exit normally.
- `requires` says that we only expect this to happen if `0 <=Int X +Int Y <Int 2 ^Int 256` (no overflow).

```k
    claim [add-positive]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                 </callStack>
          <program>   #binRuntime(ERC20)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>

          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>

          <callData> #abiCallData("add", #uint256(X), #uint256(Y)) </callData>
          <k>          #execute   => #halt ...          </k>
          <output>     .ByteArray => #buf(32, X +Int Y) </output>
          <statusCode> _          => EVMC_SUCCESS       </statusCode>

     requires #rangeUInt(256, X)
      andBool #rangeUInt(256, Y)
      andBool #rangeUInt(256, X +Int Y)
```

### Add Negative Case

- `<callData>` says we are calling `add(X, Y)`.
- `<output>` says we don't care what the function outputs.
- `<statusCode>` says we expect the function to exit in `REVERT` (state rollback).
- `requires` says that we only expect this to happen if `notBool (0 <=Int X +Int Y <Int 2 ^Int 256)` (overflow occurs).
- Note that `add-positive` and `add-negative` should cover _all_ cases for `add(X, Y)`.

```k
    claim [add-negative]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                 </callStack>
          <program>   #binRuntime(ERC20)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>

          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>

          <callData> #abiCallData("add", #uint256(X), #uint256(Y)) </callData>
          <k>          #execute   => #halt ...   </k>
          <output>     .ByteArray => ?_          </output>
          <statusCode> _          => EVMC_REVERT </statusCode>

     requires #rangeUInt(256, X)
      andBool #rangeUInt(256, Y)
      andBool notBool #rangeUInt(256, X +Int Y)
```

### Bad Add Failing Negative Case

- `<callData>` says we are calling `badAdd(X, Y)`.
- `<output>` says we don't care what the function returns.
- `<statusCode>` says we expect the function to exit in `REVERT` (state rollback).
- `requires` says that we only expect this to happen if `notBool (0 <=Int X +Int Y <Int 2 ^Int 256)` (overflow occurs).
- This proof _fails_, because the function `badAdd` fails to call `REVERT` on overflow.

```k
    claim [badAdd-negative]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                 </callStack>
          <program>   #binRuntime(ERC20)                         </program>
         <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>

          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>

          <callData> #abiCallData("badAdd", #uint256(X), #uint256(Y)) </callData>
          <k>          #execute   => #halt ...          </k>
          <output>     .ByteArray => ?_                 </output>
          <statusCode> _          => EVMC_REVERT        </statusCode>

     requires #rangeUInt(256, X)
      andBool #rangeUInt(256, Y)
      andBool notBool #rangeUInt(256, X +Int Y)
```

### Exception handling Success

```k
    claim [calculateBill.success]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                 </callStack>
          <program>   #binRuntime(ERC20)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>

          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>

          <callData> #abiCallData("calculateBill", #uint256(X)) </callData>
          <k>          #execute   => #halt ...   </k>
          <output>     .ByteArray => ?_          </output>
          <statusCode> _          => EVMC_SUCCESS </statusCode>

     requires #rangeUInt(256, X)
     andBool #rangeUInt(256, X +Int X)
```

### Exception handling Revert

```k
    claim [calculateBill.revert]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                 </callStack>
          <program>   #binRuntime(ERC20)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>

          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>

          <callData> #abiCallData("calculateBillBad", #uint256(X)) </callData>
          <k>          #execute   => #halt ...   </k>
          <output>     .ByteArray => ?_          </output>
          <statusCode> _          => EVMC_REVERT </statusCode>

     requires #rangeUInt(256, X)
     andBool #rangeUInt(256, X +Int X)
```

### Over use of gas

```k
   claim [getBillsBAD.revert]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                 </callStack>
          <program>   #binRuntime(ERC20)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>

          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas> GAVAIL </gas>
          <gasLimit> GLIMIT </gasLimit>
         <gasUsed> GUSED => GUSED +Int GLIMIT -Int GAVAIL </gasUsed>
         
          <callValue>  0           => ?_ </callValue>
          <substate> _             => ?_ </substate>

          <callData>   #abiCallData("getBillsBAD", #uint256(X))  </callData>
          <k>          #execute   => #halt ...        </k>
          <output>     _          => ?_               </output>
          <statusCode> _          => EVMC_REVERT      </statusCode>

       requires #rangeAddress(X)
       andBool GUSED >Int GLIMIT
    

```

```k
   claim [getBills.success]:
         <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                 </callStack>
          <program>   #binRuntime(ERC20)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(ERC20)) </jumpDests>

          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas> GAVAIL </gas>
          <gasLimit> GLIMIT </gasLimit>
         <gasUsed> GUSED => GUSED +Int GLIMIT -Int GAVAIL </gasUsed>
          <callValue>  0           => ?_ </callValue>
          <substate> _             => ?_ </substate>

          <callData>   #abiCallData("getBills", #uint256(X))  </callData>
          <k>          #execute   => #halt ...        </k>
          <output>     _          => ?_               </output>
          <statusCode> _          => EVMC_SUCCESS      </statusCode>


       requires #rangeAddress(X)
       andBool GLIMIT >=Int GUSED

```

### Signature Reply Attack

<!-- ```k
   claim [attack.success]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                      </callStack>
          <program>   #binRuntime(Attacker)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(Attacker)) </jumpDests>
          <static>    false                                      </static>

          <id>         ACCTID      => ?_ </id>
          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>
          <substate> _             => ?_ </substate>

          <callData>   #abiCallData("attack",#uint256(Y)) </callData>
          <k>          #execute   => #halt ...        </k>
          <output>     _          => ?_               </output>
          <statusCode> _          => EVMC_SUCCESS      </statusCode>

          <account>
            <acctID> ACCTID </acctID>
            <storage> _ACCT_STORAGE </storage>
            ...
          </account>

       requires Y =/=Int 0

``` -->
<!-- 
```k
   claim [attack.revert]:
          <mode>     NORMAL   </mode>
          <schedule> ISTANBUL </schedule>

          <callStack> .List                                      </callStack>
          <program>   #binRuntime(Attacker)                         </program>
          <jumpDests> #computeValidJumpDests(#binRuntime(Attacker)) </jumpDests>
          <static>    false                                      </static>

          <id>         ACCTID      => ?_ </id>
          <localMem>   .Memory     => ?_ </localMem>
          <memoryUsed> 0           => ?_ </memoryUsed>
          <wordStack>  .WordStack  => ?_ </wordStack>
          <pc>         0           => ?_ </pc>
          <endPC>      _           => ?_ </endPC>
          <gas>        #gas(_VGAS) => ?_ </gas>
          <callValue>  0           => ?_ </callValue>
          <substate> _             => ?_ </substate>

          <callData>   #abiCallData("_attack",#uint256(Y)) </callData>
          <k>          #execute   => #halt ...        </k>
          <output>     _          => ?_               </output>
          <statusCode> _          => EVMC_REVERT      </statusCode>

          <account>
            <acctID> ACCTID </acctID>
            <storage> _ACCT_STORAGE </storage>
            ...
          </account>

       requires Y =/=Int 0

```  -->

```k
endmodule
```
