# Use Cases

## Intra-file Variable Security Regions (VSR)

[StrongBox UC flag: `uc_secure_regions`]

Communicating classified materials, grand jury testimony, national secrets, etc.
require the highest level of discretion when handled, yet sensitive information
like this often appears within a (much) larger amount of data that we care less
about in context.

In this scenario, a user wants to classify one or more regions of a file as more
sensitive than the others. For example, perhaps banking transaction information
is littered throughout a document; perhaps passwords and other sensitive or
compromising information exists within a *much* larger data file. This sensitive
information would be encrypted using a less performant (sometimes *dramatically*
so) cipher in exchange for a stronger security guarantee.

The user will not experience a significant performance hit when perusing the
data if the bulk of it is encrypted using a high performance cipher. Similarly,
the more sensitive data regions are future-proofed and more resilient to
attack.

Terminology: "a VSR" is a region of a file that is crypted with the swap cipher
cipher than the remaining majority of the file, which is crypted using the
primary cipher.

Benefit: we can "future-proof" our encrypted highly sensitive data against more
powerful future attacks/less trustworthy ciphers while preserving the
performance win from using a faster less secure cipher.

### Issues

- Where to store the VSRs?

> The data can be stored in "reserved nuggets" which reduce the available space
on the drive by some amount proportional to the total number of VSRs in the
filesystem.

- What do VSRs have to do with our cipher switching strategies?

> Using a slightly modified version of the mirrored cipher switching strategy,
we can effectively "reserve" a portion of the backing store for the VSRs while
the remaining space is used for normal data encryption.

- How to communicate intent down the stack?

> In an ideal implementation, the low level I/O API (i.e. `write()` in C) would
> be modified to include an extra security parameter so that VSR writes could be
> distinguished from normal writes to StrongBox. Reads would function as normal
> except when an attempt is made to read a VSR; in this case, the read would be
> transparently mapped to the appropriate location on disk where the VSR resides
> and the data decrypted using the appropriate cipher.
>
> Unfortunately, the BUSE subsystem on which StrongBox is based does not support
> aberrant low level I/O requests natively, making a literal implementation an
> unattractive prospect. Hence, for our purposes, we use POSIX message queues
> (IPC) to communicate our security parameter down the stack. In fact, some form
> of the mirrored cipher strategy (but with special write rules rather than dumb
> mirroring) seems well suited to this purpose, where the primary cipher on
> partition 1 is fast and weak while the swap cipher (for the VSRs) on partition
> 2 is slow and strong.

### Tradeoffs

- The amount of wasted space (if there is any) increases proportional to the
  number of VSR-enabled files

> This is because the variable security regions of various files are aggregated
> and encrypted together within the same set of reserved nuggets. The number of
> nuggets reserved in this way is currently 50% of total available nuggets via a
> slightly modified version of the mirrored swap strategy.

- Slower than exclusively using the weakest cipher to crypt a file's nuggets,
  but the VSR content is stored more securely.

- Weaker security guarantees than using the strongest cipher to crypt the
  majority of a file's contents, but there is less I/O latency when interacting
  with said file.

### Proto Threat Model

- Encrypted data at rest becomes more resilient to targeted attacks, especially
  if the user is concerned about the security properties of a particular cipher,
  or feel that certain potentially powerful adversaries (i.e. nation-state
  adversaries) might have means to compromise a reduced round cipher through
  brute force, side channel, or etc. Freestyle, for instance, is more resilient
  to offline brute force attacks thanks to output randomization and the like but
  is much slower in practice than something like ChaCha20.

### Related Work

- Goodman et al. `An Energy/Security Scalable Encryption Processor Using an
  Embedded Variable Voltage DC/DC Converter`
- Batina et al. `Energy, performance, area versus security trade-offs for stream
  ciphers`

### Progress

- Implementation exists based on the mirrored swap strategy
- An implementation based on forward and aggressive swap strategies is theorized
- Current results
    - Read operations to non-VSR regions match StrongBox baseline performance
    - Write operations to non-VSR regions match StrongBox baseline performance
    - Read operations to VSR regions match StrongBox baseline performance when
      using an equivalent cipher
    - Write operations to VSR regions match StrongBox baseline performance when
      using an equivalent cipher
    - Whole file I/O is slower than or equal to baseline StrongBox whole file
      I/O
        - This depends on the proportion of VSR-protected data in a file
          compared to non-VSR data

## Balancing Security Goals and the Current Energy Budget

[StrongBox UC flag: `uc_fixed_energy`]

When our mobile devices enter power saving mode, it is usually because the total
energy/power budget for the device has become constrained for one reason or
another.

When a device enters this mode, all software and components are configured by
the OS to use as little of the available energy as possible. The filesystem
should be made to behave in a manner that is energy-aware as well.

Our goal is to use as little energy as possible (while reasonably preserving
filesystem performance) until the energy budget changes or the device dies.

Benefit: When constantly streaming data, e.g. using DLNA to stream a high
resolution video wirelessly to a TV on the same network, the ability to adapt to
time-varying data rates and QoS requirements while maintaining confidentiality
and integrity guarantees is paramount. This can be done by trading off a set of
security guarantees with respect to the energy spent crypting each bit. With
cipher switching, the filesystem can react dynamically to the system's total
energy budget while still aiming for the most performant (least latency)
configuration.

### Issues

- Total benefit will depend on which swap strategy is used to implement this
   - Candidate strategies are: forward and aggressive

- Total benefit is likely workload dependent
    - Read dominant vs write dominant
    - Which nuggets are hit the most during workload I/O
        - Referred to below as **hot nuggets** and **hot flakes**

- Why not default to the highest/lowest security cipher?

> Because we are trying to optimize for high performance/low latency at the same
> time we are optimizing for low energy use. These are competing concerns.

- Are gains eaten by the switching process?

> ~~Depends on the cipher switching strategy used~~ It is workload dependent. We
> observe acceptable performance near baseline for workloads that end up with
> many hot nuggets, especially if they are read-heavy; for workloads that touch
> a nugget once or twice and then never again we observe a decided performance
> degradation.

- How to communicate energy-efficiency intent down the stack?

> We have decided to use POSIX message queues (IPC) for this. See
> `uc_secure_regions` section above for more details on why we favor this over
> an implementation that explicitly modifies the low level I/O API.

### Tradeoffs

- We trade security of hot nuggets for reduced energy consumption when the
  device is in a power saving mode

- We trade energy efficiency of hot nuggets for greater security when the
  device is not in a power saving mode

### Proto Threat Model

- Confidentiality and integrity against active, passive, and offline/brute force
  attacks against FDE with respect to energy consumption

### Related Work

- Potlapally et al. `Analyzing the Energy Consumption of Security Protocols`
- Goodman et al. `An Energy/Security Scalable Encryption Processor Using an
  Embedded Variable Voltage DC/DC Converter`
- Batina et al. `Energy, performance, area versus security trade-offs for stream
  ciphers`

### Progress

- Implementation exists based on the forward and aggressive swap strategies
- The relationship between energy use and latency is linear. Hence, a reduction
  in latency translates directly into a reduction in energy use. A cipher that
  does not exhibit this behavior would be interesting to behold.
- Current results
    - ???

## Lockdown: Securing Device Data Under Duress

[StrongBox UC flag: `uc_lockdown`]

Nation-state and other adversaries have truly extensive compute resources at
their disposal, as well as knowledge of side-channels and access to technology
like q-bit computers.

Suppose one were attempting to re-enter a country through a border checkpoint
after visiting family when one is stopped. Your mobile device is confiscated and
placed in custody of the State. In such a scenario, it would be useful if the
device could swap itself into a more secure state *as quickly as possible*.

Benefit: greater security guarantee achieved using the highest security
encryption available versus powerful adversaries with unknown means and motive.

### Issues

- How do we delete the less secure region of the disk both quickly and
  effectively? TRIM?

### Tradeoffs

- (TODO)

### Proto Threat Model

- (TODO: expand this more)

### Related Work

- (TODO: is there any?)

### Progress

 - Implementation exists based on the vanilla mirrored strategy
 - Results on the mirrored swap strategy using with-cipher-switching (WCS) tests
   are in
      - Filebench results ???

## Detecting and Responding to End-of-Life Slowdown in Solid State Drives

[StrongBox UC flag: `uc_offset_slowdown`]

Due to garbage collection and the append-mostly nature of SSDs and other NAND
devices, as free space becomes constrained, performance drops off a cliff. This
is a well-studied issue (see related work).

If the filesystem is made aware when the backing store is in such a state, we
can offset some of the (drastic) performance loss by swapping the ciphers of hot
nuggets to the fastest cipher available until the disk space problem is
remedied, after which the system can detect return the swapped nuggets to their
former encrypted state.

Benefit: we can mitigate the performance loss of a slowing SSD by using a faster
but less secure cipher.

### Issues

- How to communicate down the stack that EOL slowdown was detected?

> We have decided to use POSIX message queues (IPC) for this.

### Tradeoffs

- (TODO)

### Proto Threat Model

- (TODO: expand this more)

### Related Work
- (?) Lots of consumer reports/studies on this to cite
- (?) Limplock
- (?) Tiny-tail flash: Near-perfect elimination of garbage collection tail latencies in NAND SSDs
- (TODO: perhaps add a lot of Har's work here)

### Progress

 - Implementation exists
