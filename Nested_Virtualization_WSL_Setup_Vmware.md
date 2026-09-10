# Enabling Nested Virtualization and Installing WSL2 / Docker in a VMware VM

Goal: run WSL2 (and Docker Desktop) **inside** a Windows VM hosted on VMware Workstation.

This requires **nested virtualization** — the guest needs its own working VT-x/AMD-V. Windows will not hand that over while Hyper-V or VBS is running on the host, so most of the work happens host-side.

---

## 1. Free the hardware virtualization extensions on the host

All three of these are needed. `bcdedit` alone is not sufficient — Virtualization-Based Security will relaunch the hypervisor at boot regardless of that setting.

### 1a. Disable Core isolation / Memory integrity

**Windows Security → Device security → Core isolation details → Memory integrity: Off**

If the toggle is greyed out or the machine is domain-joined, Device Guard / Credential Guard is enforced by policy or registry. See [Microsoft's instructions for disabling Device Guard](https://answers.microsoft.com/en-us/windows/forum/all/how-to-disable-device-guard/5f29388b-b59b-44cb-ae16-7f60aee2a449). The relevant key is `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`.

### 1b. Remove the Hyper-V optional features

Elevated PowerShell:

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
```

> `Disable-WindowsOptionalFeature` has **no `-All` parameter** — that flag only exists on `Enable-WindowsOptionalFeature`, where it pulls in parent features. Passing it here throws `NamedParameterNotFound`.
>
> "Feature name not recognized" on some lines is harmless; it just means that feature isn't present on your Windows edition.

### 1c. Turn off the hypervisor launch

Elevated Command Prompt or PowerShell:

```cmd
bcdedit /set hypervisorlaunchtype off
```

**Reboot the host.**

---

## 2. Verify the hypervisor is actually gone

Run `msinfo32` and look at the bottom of **System Summary**:

| What you see | Meaning |
|---|---|
| "A hypervisor has been detected..." | Still running — something in step 1 didn't take. Go back to 1a. |
| Four "Hyper-V Requirements" lines reading **Yes** | Hypervisor is off, VT-x is free. |

Cross-check with:

```cmd
bcdedit /enum {current}
```

`hypervisorlaunchtype` should read `Off`.

> On the **host**, Task Manager's "Virtualization: Enabled" line is not a reliable check — when Hyper-V is running that line is replaced entirely. Use `msinfo32`. Inside the **guest**, however, Task Manager → Performance → CPU → "Virtualization: Enabled" *is* the correct way to confirm nested VT-x arrived.

Also confirm VT-x/AMD-V (and ideally VT-d/IOMMU) are enabled in BIOS/UEFI. No amount of Windows configuration helps if they're off at the firmware level.

---

## 3. Enable nested virtualization on the VM

The VM must be **fully powered off** — not suspended.

**GUI (recommended):** VM → Settings → Hardware → Processors → check **Virtualize Intel VT-x/EPT** (or **AMD-V/RVI**).

**Leave "Virtualize CPU performance counters" UNCHECKED.** vPMC is a separate feature only needed for hardware profiling inside the guest (perf, VTune). Enabling it on a host that can't supply the PMU produces:

```
Module 'VPMC' power on failed.
```

**Manual `.vmx` edit** (close VMware Workstation first):

```plaintext
vhv.enable = "TRUE"
```

That single line covers both Intel and AMD — `amd-v = "TRUE"` is **not** a valid `.vmx` key and does nothing.

`hypervisor.cpuid.v0 = "FALSE"` hides the hypervisor CPUID bit from the guest. It is **optional** on modern Workstation and only relevant for older nested-Hyper-V setups or software that refuses to run under a detected hypervisor. Add it only if you hit that specific problem.

### Resource sizing

WSL2 runs a real Linux VM inside your guest. Allocate generously or Docker will crawl:

- **4+ vCPUs**
- **8 GB RAM minimum**, 16 GB if you're running containers seriously
- **60 GB+ disk** — Docker images add up fast

---

## 4. Enable the virtualization features inside the guest

On current Windows 10/11 builds, `wsl --install` enables these automatically, so this step is usually unnecessary. Use it only if `wsl --install` fails:

```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

Reboot the guest.

---

## 5. Install WSL2 in the guest

Install the WSL runtime without a distribution:

```powershell
wsl --install --no-distribution
```

> `wsl --update` only updates an existing WSL kernel — it does not install WSL. Use `--no-distribution` if you want the runtime alone.

Set the default version (already 2 on modern builds, but harmless to be explicit):

```powershell
wsl --set-default-version 2
```

List and install a distribution:

```powershell
wsl --list --online
wsl --install -d kali-linux
```

Confirm it landed on version 2:

```powershell
wsl -l -v
```

The `VERSION` column must read `2`. If it reads `1`, nested virtualization isn't working — return to step 2.

---

## 6. Install Docker Desktop in the guest

Download and run the installer. During setup, keep **"Use WSL 2 instead of Hyper-V"** selected.

Verify the engine actually started rather than silently failing:

```powershell
docker run hello-world
```

---

## Choosing a configuration

You cannot have working nested virtualization *and* host-side Hyper-V simultaneously. Pick one:

### Option A — Nested virtualization in the VM (this guide)

WSL2 and Docker run **inside** the VM.

```cmd
bcdedit /set hypervisorlaunchtype off
```
- Core isolation / Memory integrity: **off**
- VM → Processors → **Virtualize Intel VT-x/EPT: enabled**
- VM → Processors → Virtualize CPU performance counters: **disabled**

**Trade-off:** the host loses WSL2, Docker Desktop, Hyper-V, Windows Sandbox, Memory integrity, and Credential Guard. The VM gets full hardware-accelerated virtualization.

### Option B — Hyper-V on the host

WSL2 and Docker run **on the host**.

```cmd
bcdedit /set hypervisorlaunchtype auto
```
- Re-enable the optional features from step 1b
- VM → Processors → **disable both** Virtualize Intel VT-x/EPT and Virtualize CPU performance counters

**Trade-off:** VMware Workstation 15.5+ still runs in this mode — it switches to a user-level monitor on top of the Windows Hypervisor Platform — but VMs run noticeably slower and nested virtualization is unavailable. Older Workstation versions refuse to start VMs entirely.

**Reboot after switching either direction.**

---

## Quick troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Module 'VPMC' power on failed` | vPMC enabled, host PMU unavailable | Uncheck "Virtualize CPU performance counters" |
| `Virtualized Intel VT-x/EPT is not supported on this platform` | Host hypervisor still holding VT-x | Complete steps 1a–1c, verify with step 2 |
| WSL distro shows `VERSION 1` | Nested virt not reaching the guest | Verify step 2, confirm VT-x checkbox in step 3 |
| Docker Desktop won't start | WSL2 backend unavailable | Run `wsl -l -v`; fix WSL before Docker |
| `NamedParameterNotFound` on `-All` | Wrong cmdlet parameter | Drop `-All` from `Disable-WindowsOptionalFeature` |
