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
data if the bulk of it is encrypted using a high performance cipher.

Benefit: we can "future-proof" our encrypted highly sensitive data against more
powerful future attacks/less trustworthy ciphers while preserving the
performance win from using a faster less secure cipher.

### Issues

- Where to store the VSRs?

> The data can be stored in "reserved nuggets" (reducing the available space on
> the drive by some amount proportional to the total number of VSRs in the
> filesystem.

- How to communicate intent down the stack?

> We've decided to use POSIX message queues (IPC) for this.

### Tradeoffs

- The amount of wasted space increases proportional to the number of VSR-enabled
  files

> This is because the variable security regions of various files are aggregated
> and encrypted together within the same set of reserved nuggets (the number of
> nuggets reserved in this way is currently user-defined).

- Slower than exclusively using the weakest cipher to crypt the file's nuggets,
  but it is more secure.

- Weaker security guarantees than using the strongest cipher to crypt the file's
  contents, but it takes longer to perform I/O on the file.

### Proto Threat Model

- Encrypted data becomes more resilient to targeted attacks, especially if the
  user is concerned about the security properties of a particular cipher, or
  feel that certain potentially powerful adversaries (i.e. nation-state
  adversaries) might have means to compromise a reduced round cipher through
  brute force, side channel, or etc.

- (TODO: expand this more)

### Related Work

- TODO: add variable encryption papers here when I get back to Chicago (it's on
  my desk)

### Progress

 - [x] Implementation exists
    - [ ] Implementation completed
 - [ ] Results exists

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

Benefit: With cipher switching, the filesystem can react dynamically to the
system's total energy budget while still aiming for the most performant
configuration.

### Issues

- Total benefit will depend on which swap strategy is used to implement this

- Total benefit is likely workload dependent
    - Read dominant vs write dominant
    - Which nuggets are hit the most during workload I/O
        - Referred to below as **hot nuggets**
    - Et cetera

- Why not default to the highest/lowest security cipher?

> Because we're also trying to optimize for high performance/low latency and low
> energy use

- Are gains eaten by the switching process?

> Depends on the cipher switching strategy used

- How to communicate intent down the stack?

> We've decided to use POSIX message queues (IPC) for this.

### Tradeoffs

- We trade security of hot nuggets for reduced energy consumption when the
  device is in a power saving mode

- We trade energy efficiency of hot nuggets for greater security when the
  device is not in a power saving mode

### Proto Threat Model

- Confidentiality and integrity against active, passive, and offline/brute force
  attacks against FDE

- (TODO: expand this more)

### Related Work

- (TODO)

### Progress

 - [x] Implementation exists
    - [ ] Implementation completed
 - [ ] Results exists

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

> We've decided to use POSIX message queues (IPC) for this.

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

 - [ ] Implementation exists
    - [ ] Implementation completed
 - [ ] Results exists

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

- (TODO)

### Tradeoffs

- (TODO)

### Proto Threat Model

- (TODO: expand this more)

### Related Work

- (TODO)

### Progress

 - [ ] Implementation exists
    - [ ] Implementation completed
 - [ ] Results exists

## Automated location-based Security versus Performance Tradeoff

[StrongBox UC flag: `uc_auto_locations`]

Suppose you own a startup that does sensitive work, e.g. government contractor.
When the devices (laptops, tablets) you lend to your employees are taken off the
premises, it would be beneficial if the regions of the drive containing
sensitive information were encrypted using the most powerful cipher available.
While on the premises, it might behoove the startup to lower the security on
these regions for performance or other reasons.

Benefit: the filesystem can become more or less performance/energy efficient
depending on where it determines it is.

### Issues

- Locations can be faked?

### Tradeoffs

- (TODO)

### Proto Threat Model

- (TODO)

### Related Work

- (TODO)

### Progress

 - [ ] Implementation exists
    - [ ] Implementation completed
 - [ ] Results exists

## ???

[StrongBox UC flag: `uc_???`]

???

### Issues

- ???

### Tradeoffs

- ???

### Proto Threat Model

- ???

### Related Work

- ???

### Progress

 - [ ] Implementation exists
    - [ ] Implementation completed
 - [ ] Results exists

# Combinations?

Are there any combinations of the aforesaid that might make for an interesting
use case scenario?
