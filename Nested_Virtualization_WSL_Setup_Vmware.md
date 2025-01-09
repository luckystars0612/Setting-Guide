
# Steps to Enable Nested Virtualization and Install WSL on VMware

## 1. Disable Hypervisor on the Host OS
Run the following command in an elevated Command Prompt (on the host OS) to turn off the hypervisor:
```cmd
bcdedit /set hypervisorlaunchtype off
```
Reboot the host machine after running this command.

---

## 2. Configure the VMware VM for Nested Virtualization
Edit the `.vmx` file of your Windows VM and add the following lines:
```plaintext
hypervisor.cpuid.v0 = "FALSE"
vhv.enable = "TRUE"
amd-v = "TRUE"
```
Save the file and start the VM.

---

## 3. Enable Virtualization Features in the VM
After starting the Windows VM, open **PowerShell** with Administrator rights and run the following commands to enable virtualization features:
```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```
Reboot the VM after executing these commands.

---

## 4. Install WSL Without a Distribution
Install WSL (without a distribution) by running:
```powershell
wsl --install --no-distribution
```

## 5. Change to WSL version 2
```powershell
wsl --set-default-version 2
```

---

## 6. List Available WSL Distributions
To see all available distributions for installation, run:
```powershell
wsl --list --online
```

---

## 7. Install a Specific Distribution
Install a specific WSL distribution (e.g., Kali Linux) by running:
```powershell
wsl --install -d kali-linux
```

---

## Notes
- Ensure virtualization is enabled by checking **Task Manager** > **Performance** tab > "Virtualization" (should say **Enabled**).
- Always restart the system after enabling features or making configuration changes.

---

