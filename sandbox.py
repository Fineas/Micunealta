import os
import time
import logging
import subprocess
from pathlib import Path

class Sandbox:
    def __init__(self, arch, sample_path):
        self.sample_path = sample_path
        self.tcpdump_path = "dumped_resources/network_dump.pcap"
        self.arch = arch
        
    """
    """
    def start(self):
        cmd = [
            self.arch,

            # Use the q35 machine type + HVF acceleration (macOS Hypervisor.framework)
            "-machine", "pc,accel=tcg",

            # Emulate a Nehalem CPU with Hyper-V–style features on macOS
            "-cpu", "Nehalem",

            # Give the VM 4 GB of RAM
            "-m", "2G",

            # 2 CPU cores
            "-smp", "2",

            # Set RTC to localtime
            "-rtc", "base=localtime,clock=host",

            # Display defaults with visible mouse cursor
            "-display", "default,show-cursor=on",

            # Primary drive (where Windows is/will be installed)
            "-drive", "file=./hda/win10.qcow2,if=ide",

            # Provide the Windows 10 ISO on a virtual CD/DVD drive
            "-cdrom", "./img/Win10_22H2_English_x32v1.iso",
            "-boot", "d",

            # Run in snapshot mode so changes aren't persisted
            "-snapshot",

            # Networking (forward host port 2222 -> guest port 22, dump traffic)
            "-netdev", "user,id=user0,hostfwd=tcp::2222-:22",
            "-device", "e1000,netdev=user0",
            "-object", f"filter-dump,id=dump,netdev=user0,file={self.tcpdump_path}",

            # Log serial console output to a file
            "-serial", "file:sample_output.log",

            # "-monitor", "stdio",
        ]

        print("[*] Starting QEMU with command:", " ".join(cmd))
        self.qemu_process = subprocess.Popen(cmd)


    """
    ensure the SSH server is running in the Win10 guest
    copy sample file via SCP (port 2222 on the host)
    execute the sample and collect results 
    """
    def execute_sample(self):
        scp_cmd = [
            "scp", "-P", "2222",
            self.filepath,  # local path
            "user@localhost:C:\\Users\\Public\\"  # eqemu path
        ]
        subprocess.run(scp_cmd, check=True)

        ssh_cmd = [
            "ssh", "-p", "2222", "user@localhost",
            "C:\\Users\\Public\\"+self.filepath
        ]
        proc = subprocess.run(ssh_cmd, capture_output=True, text=True)
        print("[*] Malware run output:", proc.stdout)
        print("[*] Malware exit status:", proc.returncode)
        
    def copy_sample(self, sample_path):
        # Implementation for copying sample to VM
        pass
        
    def execute_sample(self):
        # Implementation for running sample
        pass
        
    def monitor_processes(self):
        # Implementation for process monitoring
        pass

    def stop(self):
        if self.qemu_process and self.qemu_process.poll() is None:
            print("[*] Stopping QEMU gracefully via monitor...")
            self.qemu_process.terminate()  # fallback if needed
        exit_code = self.qemu_process.wait()
        print(f"[*] Emulation terminated with Status Code: {exit_code}")