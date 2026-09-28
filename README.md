# FiBeWI

> **Migration :** le développement du moteur OTA se poursuit dans
> [`iobewi/services/ota`](https://github.com/iobewi/iobewi/tree/main/services/ota)
> (`iobewi-ota`). Les règles EWBT et le validateur d'image ESP sont dans
> [`iobewi-esp/hardware/ota-boot`](https://github.com/iobewi/iobewi-esp/tree/main/hardware/ota-boot).
> Ce dépôt reste disponible pour l'historique et les versions déjà épinglées.

FiBeWI is a `no_std` firmware lifecycle engine focused on transactional,
resumable updates and restart-safe A/B activation.

The repository contains a single platform-independent `fibewi` crate. ESP hardware adapters live in `espbewi`.

```text
fibewi/
└── src/
    ├── artifact / transaction / storage
    └── boot/              # pure EWBT A/B semantics + ESP image-format validator
```

## Core `fibewi`

The root crate owns:

- resumable streaming writes and durable-progress tracking;
- SHA-256 verification while bytes become durable;
- staged transaction records;
- `Staged -> Activating -> resolved` transaction semantics;
- deterministic reconciliation after restart;
- backend contracts for artifact storage and transaction metadata.

It deliberately does not know about HTTP, TLS, NVS, ESP partition tables,
bootloader executables, linker layouts, MMU/cache programming, watchdog
registers, or application configuration.

## Boot semantics

FiBeWI owns the pure, host-testable parts of the firmware lifecycle:

- EWBT transactional `otadata` encoding and A/B state transitions;
- slot-selection, activation, confirmation and rollback decisions;
- ESP application-image parsing and validation against a caller-supplied abstract `MemoryMap`.

FiBeWI does **not** own ESP flash drivers, partition-table access, concrete SoC memory maps, NVS, ROM calls, MMU/cache setup, watchdog handling, linker scripts, or an ESP bootloader executable. Those responsibilities belong to `espbewi`.

## Bootloader ownership

FiBeWI intentionally contains no ESP bootloader executable.

The ESP second-stage bootloader is owned by
[`espbewi/bootloader/esp`](https://github.com/iobewi/espbewi/tree/refactor/bootloader-owner/bootloader/esp).
It depends on FiBeWI for EWBT/A-B lifecycle policy and image-validation
semantics, while `espbewi` owns the hardware execution boundary.

```text
ESP ROM
  -> espbewi-bootloader
       -> espbewi hardware/platform
       -> fibewi::boot semantics
  -> application
```

## Tests

Host tests:

```sh
cargo test -p fibewi
```

The FiBeWI host suite includes the adversarial EWBT power-cut model
imported from the former `atomic-boot` repository.

## Status

Pre-stable. FiBeWI owns transactional firmware lifecycle semantics and pure boot-policy/image-validation logic while all concrete ESP hardware execution remains outside the repository.

## License

MIT.
