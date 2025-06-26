
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
amd-v = "TRUE"   #for amd processor
```
> ***Note: this can be done with GUI of Vmware by click processors -> Virtualize Intel VT-x/EPT or AMD-V/RVI***
Save the file and start the VM.

***Note: In newer versions of VMware Workstation, we need to disable Device Guard (or installation will fail) follow [Microsoft instruction](https://answers.microsoft.com/en-us/windows/forum/all/how-to-disable-device-guard/5f29388b-b59b-44cb-ae16-7f60aee2a449)***
---

## 3. Enable Virtualization Features in the VM (optional)
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
wsl --update
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
- This setting means you can't use Hyper-V, Docker Desktop or any other virtualization stuff on your host machine while allowing nested virtualization. If you want to enable it again, just run the following command and restart host.
```bash
bcdedit /set hypervisorlaunchtype auto
```
---

