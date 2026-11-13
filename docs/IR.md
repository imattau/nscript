# NScript IR interchange

The checked compiler lowers programs into `NostrIr`, serialized with the
schema marker `nscript-ir/0.2`. The same JSON appears on the CLI `compile
--emit ir` output and in the `nscript.ir` custom section of emitted WASM.

The interchange is non-executable. It contains resolved module identities and
hashes, declared capabilities, permissions, and typed publication operations.
Consumers MUST reject unknown schema markers rather than guessing at field
semantics. Version `0.2` adds lowered wire tags to `create_event`; operation
ordering and existing serialized field names remain stable.

The `nscript.dispatch` WASM custom section contains only the operation array
from this IR. Hosts must validate its bounds and operation-to-import mapping
before dispatching effects.
