# WolfFlow: Container/VM-Level Task Execution

## Summary

Currently WolfFlow can target hosts (Local, All Nodes, Cluster, Specific Nodes). Users should also be able to target individual Docker containers, LXC containers, and VMs directly — running commands inside them, not on the host.

## Current State

- Target `Containers` scope exists in the enum but only resolves to the **host nodes** that run those containers
- `execute_action_local` runs commands on the host OS via `tokio::process::Command`
- No mechanism to exec into a container/VM and run a command there

## What Needs to Change

### 1. New execution mode: `container_exec`

When a step targets a container, the command runs **inside** the container:
- **Docker**: `docker exec {container_name} {command}`
- **LXC**: `lxc-attach -n {container_name} -- {command}`
- **VM**: `virsh qemu-agent-command` (for libvirt) or SSH into the VM

### 2. Target resolution changes

The `Containers` target currently resolves to host nodes. It needs to also carry the container runtime + name so the execution engine knows to use `docker exec` / `lxc-attach` instead of running on the host directly.

### 3. Actions that make sense inside containers

- `RunCommand` — execute shell command inside the container
- `CheckDiskSpace` — check disk inside the container
- `UpdatePackages` — run package manager inside the container
- `RestartService` — restart a service inside the container (systemd in LXC, or process manager in Docker)

### 4. Actions that should stay host-level

- `DockerPrune`, `RestartContainer` — these manage containers from outside
- `UpdateWolfstack` — only makes sense on the host
- `CleanLogs` — journalctl is host-level

### 5. Frontend changes

- The infrastructure explorer already shows containers/VMs under each node
- When a container is selected as a target, the step should show "Executes inside container" indicator
- Some actions should be greyed out when targeting a container (e.g. DockerPrune)

### 6. VM execution

VMs are harder — no `docker exec` equivalent. Options:
- QEMU Guest Agent (`virsh qemu-agent-command`) — requires guest agent installed
- SSH — requires SSH access configured
- For native QEMU VMs: no built-in exec mechanism, SSH is the only option

## Implementation Approach

1. Add `ContainerExecContext` to the step execution — carries runtime, container name, node info
2. Modify `run_command` to optionally wrap in `docker exec` / `lxc-attach`
3. Update `resolve_targets` to return container context when scope is Containers
4. Frontend: show container-aware action filtering

## NOT doing yet — just planning.
