import re
import os
import lief
import math
import magic
import base64
import hashlib
import subprocess
from report import Report
from datetime import datetime
from abc import ABC, abstractmethod

supported_obfuscations = ["UPX"]
resources_dir = "dumped_resources"
local_func_datasets = ['datasets/pe_suspicious_function_names.txt', 'datasets/elf_suspicious_function_names.txt', 'datasets/macho_suspicious_function_names.txt']

class Sample(ABC):
    def __init__(self, filepath):
        self.filepath = filepath
        self.binary = self.load()
        self.strings = self.dump_strings()
        self.report = Report()


    """
    Load the sample as lief.Binary
    """
    def load(self):
        return lief.parse(self.filepath)


    """
    Extract printable strings from the binary
    Returns a list of strings found in the binary
    """
    def dump_strings(self, min_length=6):

        with open(self.filepath, 'rb') as f:
            data = f.read()

        pattern = re.compile(rb'[ -~\n]{' + str(min_length).encode() + rb',}')
        found = pattern.findall(data)

        return [s.decode('utf-8', errors='replace') for s in found]
    

    """
    Wrapper to extract Details about the sample such as:
        Basic properties: 
            - MD5, SHA-1, SHA-256, File Type, Magic, File Size
        History:
            - Creation Date, Last Accessed Date
        Header:
            - Optional Header, Entry Point, Compilation Time
        Sections:
            - List all sections
        Imports:
            - List all imports
        Resources:
            - SHA-256, File Type, Type, Language, Entropy
    """
    def anatomy(self):
        print("[*] Anatomy:")
        # Calculate hashes
        with open(self.filepath, 'rb') as f:
            data = f.read()
            print(f"    > MD5: {hashlib.md5(data).hexdigest()}")
            print(f"    > SHA-1: {hashlib.sha1(data).hexdigest()}")
            print(f"    > SHA-256: {hashlib.sha256(data).hexdigest()}")
        
        # File properties
        print(f"    > File Type: {magic.from_file(self.filepath)}")
        print(f"    > Magic: {magic.from_file(self.filepath, mime=True)}")
        print(f"    > File Size: {os.path.getsize(self.filepath)} bytes")

        print("\n    [*] History")
        stat = os.stat(self.filepath)
        print(f"    > Creation Time: {datetime.fromtimestamp(stat.st_ctime)}")
        print(f"    > Last Access Time: {datetime.fromtimestamp(stat.st_atime)}")

        print("\n    [*] Header Information")
        self.analyze_metadata()

        print("\n    [*] Sections")
        for section in self.binary.sections:
            print(f"\n        [*] Section: {section.name}")
            print(f"        > Virtual Address: {hex(section.virtual_address)}")
            print(f"        > Virtual Size: {hex(section.virtual_size)}")
            print(f"        > Raw Size: {hex(section.size)}")
            entropy = self.calculate_entropy(section.content)
            print(f"        > Entropy: {entropy:.2f}")
            section_md5 = hashlib.md5(bytes(section.content)).hexdigest()
            print(f"        > MD5: {section_md5}")

        print("\n    [*] Imports")
        for imp in self.binary.imports:
            print(f"    > {imp.name}")

        print("\n    [*] Resources")
        self.analyze_resources()


    """
    Compute the entropy of a memory region
    """
    def calculate_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = bytes(data).count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy


    """
    Parse the binary computing an entropy score 
    """
    def detect_obfuscation(self):
        is_obfuscated = False

        for section in self.binary.sections:
            entropy = self.calculate_entropy(section.content)
            if entropy > 7.5:  # threshold for high entropy
                print(f"High entropy section detected: {section.name} with entropy {entropy:.2f}")
                is_obfuscated = True
                
        if is_obfuscated:
            print("[*] Obfuscation detected")
            for o in supported_obfuscations:
                if o == "UPX":
                    print("[*] Checking for UPX")
                    try:
                        result = subprocess.run(['upx', '-t', self.filepath], capture_output=True, text=True)
                        if "[OK]" in result.stdout:
                            result = subprocess.run(['upx', '-d', self.filepath], capture_output=True, text=True)
                            if "Unpacked 1 file" in result.stdout:
                                print("[*] Unpacked Sample - UPX")
                                self.binary = self.load()
                                print("[*] Binary reloaded")
                            else:
                                print("[!] Failed to unpack Sample - UPX")
                        else:
                            print("[!] UPX not found")
                    except FileNotFoundError:
                        print("[!] UPX is not installed or not found in the system path.")


    """
    Analyze and categorize strings extracted from the binary:
        - Extract common strings (urls, emails)
        - Extract encoded strings (b64, hex)
        - Extract other printable strings
    """
    def analyze_strings(self):
        strings = self.strings

        url_pattern = re.compile(r'([a-zA-Z0-9+.\-]+://[^\s]+)')
        email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')

        urls = []
        emails = []
        base64_strings = []
        hex_strings = []
        others = []

        def is_base64(s):
            if len(s) < 8:
                return False
            if len(s) % 4 != 0:
                return False
            if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', s):
                return False
                
            try:
                decoded = base64.b64decode(s)
                decoded_str = decoded.decode('utf-8', errors='ignore')
                return not decoded_str.isprintable()
            except:
                return False

        def is_hex(s):
            return len(s) >= 6 and len(s) % 2 == 0 and re.fullmatch(r'[0-9A-Fa-f]+', s) is not None

        for s in strings:
            if url_pattern.search(s):
                urls.append(s)
                continue

            if email_pattern.search(s):
                emails.append(s)
                continue

            if is_base64(s):
                base64_strings.append(s)
                continue

            if is_hex(s):
                hex_strings.append(s)
                continue

            others.append(s)

        if urls:
            print("[*] URLs found:")
            for u in urls:
                print(f"   {u}")

        if emails:
            print("[*] Emails found:")
            for e in emails:
                print(f"   {e}")

        if base64_strings:
            print("[*] Base64-encoded strings found:")
            for b in base64_strings:
                print(f"   {b}")

        if hex_strings:
            print("[*] Hex-encoded strings found:")
            for h in hex_strings:
                print(f"   {h}")

        if others:
            print("[*] Other strings:")
            for o in others:
                print(f"   {o}")

    """
    Routine to unpack known packing methods
    """
    def unpack(self, packing_method):
        if packing_method.lower() == 'upx':
            try:
                result = subprocess.run(['upx', '-d', self.filepath], capture_output=True, text=True)
                if result.returncode == 0:
                    print("Successfully unpacked using UPX.")
                else:
                    print(f"Failed to unpack using UPX: {result.stderr}")
            except FileNotFoundError:
                print("UPX is not installed or not found in the system path.")
        else:
            print(f"Packing method '{packing_method}' is not supported.")


    """
    Check for embedded files in the binary using binwalk
    """
    def check_embedded_files(self):
        print("[*] Checking for embedded files...")
        try:
            result = subprocess.run(['binwalk', '-e', self.filepath], capture_output=True, text=True)
            if result.stdout:
                print(result.stdout)
        except FileNotFoundError:
            print("[!] Binwalk not found in system path")

    def analyze_functions(self, dataset_name):
        # Load suspicious functions dataset
        with open(dataset_name, 'r') as f:
            suspicious_functions = set(line.strip() for line in f)
        
        found_suspicious = []
        
        # Check imported functions against suspicious list
        for imp in self.binary.imports:
            for func in imp.entries:
                if func.name in suspicious_functions:
                    found_suspicious.append(func.name)
        
        if found_suspicious:
            print("[*] Suspicious functions found:")
            for func in found_suspicious:
                print(f"    > {func}")


    @abstractmethod
    def analyze_metadata(self):
        pass


    @abstractmethod
    def analyze_resources(self):
        pass    


    """
    STEP 4
        Part 1: GENERIC ANALYSIS
            - Analyze the binary for obfuscation
                - If known obfuscation is used, attempt to decode it 
            - Analyze the strings 
                - Extract common strings (urls, emails, etc.)
                - Extract encoded strings (b64, hex, etc.)
                - Extract any other printable strings
            - Analyze the functions
                - Dump all functions
                    - If known suspicious functions are found, explore how and where they are used
                    - Generate graph with function calls
            - Check for rxw sections (either mapped at runtime or at compile time)

        Part 2: RE-ANALYZE 2nd STAGES
            - If a new binary is downlaoded 
            - If a new memory region is mapped and executed
            - If we successfully decoded an obfuscated binary 
    """
    @abstractmethod
    def static_analysis(self):
        pass


    """
    STEP 5
        Part 1: DYNAMIC ANALYSIS
            - Create dynamic environment to run the binary 
            - Run the binary in the dynamic environment
            - Analyze the behavior of the binary
                - Extract all networking interactions 
                - Extract all file operations 
                - Trace all the syscalls 
                - Extract all permissions  
                - Dump the memory mappings (at the start, midway, and at the end)
            - Look for forks or new threads

        Part 2: RE-ANALYZE child processes
            - If a new process is created, dump it and re-analyze it
            - If a new thread is created, follow it 
    """    
    def dynamic_analysis(self):
        pass


    """
    Cast findings to the Report class and save the results
    """
    def results(self, json_dump, pdf_dump):
        if json_dump:
            self.report.export_json(f"{self.filepath}_report.json")
        if pdf_dump:
            self.report.export_pdf(f"{self.filepath}_report.pdf")


"""
+---------------------------------+
| Sample Class for the ELF Format |
+---------------------------------+
"""
class ElfSample(Sample):
    def static_analysis(self):
        self.anatomy()
        self.detect_obfuscation()
        self.analyze_functions(local_func_datasets[1])

    def analyze_metadata(self):
        print("[*] ELF Header Analysis")
        header = self.binary.header
        
        for field in dir(header):
            if not field.startswith('_'):
                value = getattr(header, field)
                if not callable(value):
                    if isinstance(value, int):
                        print(f"    > {field}: {hex(value)}")
                    else:
                        print(f"    > {field}: {value}")
        
        print(f"\n    [*] Entry Point: {hex(self.binary.entrypoint)}")
        print("\n    [*] Sections:")
        for section in self.binary.sections:
            print(f"      {section.name}")

    def analyze_resources(self):
        print("[*] ELF Resources Analysis")
        # ELF binaries store resources in sections
        for section in self.binary.sections:
            if section.size > 0:
                content = bytes(section.content)
                sha256 = hashlib.sha256(content).hexdigest()
                file_type = magic.from_buffer(content)
                entropy = self.calculate_entropy(content)
                
                print(f"\n    [*] Section: {section.name}")
                print(f"    > SHA-256: {sha256}")
                print(f"    > File Type: {file_type}")
                print(f"    > Size: {hex(section.size)}")
                print(f"    > Entropy: {entropy:.2f}")


"""
+--------------------------------+
| Sample Class for the PE Format |
+--------------------------------+
"""
class PeSample(Sample):
    def static_analysis(self):
        self.anatomy()
        self.detect_obfuscation()
        self.analyze_functions(local_func_datasets[0])

    def analyze_metadata(self):
        header = self.binary.optional_header
        
        for field in dir(header):
            if not field.startswith('_'):  # Skip internal attributes
                value = getattr(header, field)
                if not callable(value):  # Skip methods
                    if isinstance(value, int):
                        print(f"    > {field}: {hex(value)}")
                    else:
                        print(f"    > {field}: {value}")
        
        print(f"\n    [*] Compilation Timestamp: {self.binary.header.time_date_stamps}")
        print(f"    [*] Entry Point: {hex(self.binary.optional_header.addressof_entrypoint)}")
        
        print("\n    [*] Sections:")
        for section in self.binary.sections:
            print(f"    > {section.name}")

    def analyze_resources(self):
        resources = self.binary.resources
        resource_types = {
            1: ("CURSOR", ".cur"),
            2: ("BITMAP", ".bmp"),
            3: ("ICON", ".ico"),
            4: ("MENU", ".rc"),
            5: ("DIALOG", ".dlg"),
            6: ("STRING", ".txt"),
            7: ("FONTDIR", ".fnt"),
            8: ("FONT", ".fon"),
            9: ("ACCELERATOR", ".rc"),
            10: ("RCDATA", ".bin"),
            11: ("MESSAGETABLE", ".bin"),
            12: ("GROUP_CURSOR", ".cur"),
            14: ("GROUP_ICON", ".ico"),
            16: ("VERSION", ".txt"),
            17: ("DLGINCLUDE", ".dlg"),
            19: ("PLUGPLAY", ".bin"),
            20: ("VXD", ".vxd"),
            21: ("ANICURSOR", ".ani"),
            22: ("ANIICON", ".ani"),
            23: ("HTML", ".html"),
            24: ("MANIFEST", ".xml")
        }

        if resources:
            # Create / Clean dumped_resources directory
            if os.path.exists(resources_dir):
                for file in os.listdir(resources_dir):
                    os.remove(os.path.join(resources_dir, file))
            else:
                os.makedirs(resources_dir)

            # Dump resources
            for resource_type in resources.childs:
                type_info = resource_types.get(resource_type.id, f"Unknown ({resource_type.id})")
                type_name, type_ext = type_info
                for resource_id in resource_type.childs:
                    for resource_lang in resource_id.childs:
                        content = bytes(resource_lang.content)
                        sha256 = hashlib.sha256(content).hexdigest()
                        file_type = magic.from_buffer(content)
                        entropy = self.calculate_entropy(content)
                        
                        print(f"\n    > Type: {type_name}")
                        print(f"    > SHA-256: {sha256}")
                        print(f"    > File Type: {file_type}")
                        print(f"    > Language: {resource_lang.id}")
                        print(f"    > Entropy: {entropy:.2f}")

                        # Extract resource to file
                        output_path = os.path.join(resources_dir, f"resource_{type_name}_{resource_id.id}{type_ext}")
                        with open(output_path, 'wb') as f:
                            f.write(bytes(resource_lang.content))
                        print(f"    > Extracted to: {output_path}")
            print()
        else:
            print("    [!] No resources found\n")


"""
+-----------------------------------+
| Sample Class for the Macho Format |
+-----------------------------------+
"""
class MachoSample(Sample):
    def static_analysis(self):
        self.anatomy()
        self.detect_obfuscation()
        self.analyze_functions(local_func_datasets[2])

    def analyze_metadata(self):
        header = self.binary.header
        
        for field in dir(header):
            if not field.startswith('_'):
                value = getattr(header, field)
                if not callable(value):
                    if isinstance(value, int):
                        print(f"    > {field}: {hex(value)}")
                    else:
                        print(f"    > {field}: {value}")
        
        print(f"\n    [*] Entry Point: {hex(self.binary.entrypoint)}")
        print("\n    [*] Segments:")
        for segment in self.binary.segments:
            print(f"       > {segment.name}")

    def analyze_resources(self):
        # Mach-O resources are typically in the __DATA segment
        for segment in self.binary.segments:
            if segment.name == "__DATA":
                for section in segment.sections:
                    content = bytes(section.content)
                    sha256 = hashlib.sha256(content).hexdigest()
                    file_type = magic.from_buffer(content)
                    entropy = self.calculate_entropy(content)
                    
                    print(f"\n    [*] Section: {section.name}")
                    print(f"    > SHA-256: {sha256}")
                    print(f"    > File Type: {file_type}")
                    print(f"    > Size: {hex(section.size)}")
                    print(f"    > Entropy: {entropy:.2f}")