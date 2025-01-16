import re
import os
import lief
import math
import base64
import subprocess
from report import Report
from abc import ABC, abstractmethod

supported_obfuscations = ["UPX"]
resources_dir = "dumped_resources"

class Sample(ABC):
    def __init__(self, filepath):
        self.filepath = filepath
        self.binary = self.load()
        self.strings = self.dump_strings()
        self.report = Report()

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

    @abstractmethod
    def analyze_functions(self):
        pass

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
    def static_analysis(self):
        self.detect_obfuscation()
        self.analyze_strings()
        self.analyze_functions()
        self.analyze_metadata()
        self.analyze_resources()

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

    def results(self, json_dump, pdf_dump):
        if json_dump:
            self.report.export_json(f"{self.filepath}_report.json")
        if pdf_dump:
            self.report.export_pdf(f"{self.filepath}_report.pdf")

class ElfSample(Sample):
    def analyze_functions(self):
        # Analyze functions and API calls
        for function in self.binary.functions:
            print(f"Function: {function.name}")

    def analyze_metadata(self):
        # Analyze ELF headers
        print(f"Entry point: {self.binary.header.entrypoint}")

    def analyze_resources(self):
        # ELF typically doesn't have resources like PE
        print("No resources to analyze in ELF.")

class PeSample(Sample):
    def analyze_functions(self):
        # Load suspicious functions dataset
        with open('datasets/pe_suspicious_function_names.txt', 'r') as f:
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
                print(f"   {func}")

    def analyze_metadata(self):
        # Analyze PE headers
        print("[*] PE Optional Header Analysis")
        header = self.binary.optional_header
        
        for field in dir(header):
            if not field.startswith('_'):  # Skip internal attributes
                value = getattr(header, field)
                if not callable(value):  # Skip methods
                    if isinstance(value, int):
                        print(f"{field}: {hex(value)}")
                    else:
                        print(f"{field}: {value}")
            
        # Check compilation timestamp
        print(f"Compilation Timestamp: {self.binary.header.time_date_stamps}")
        
        # Check for digital signatures
        if self.binary.has_signatures:
            print("[*] Digital signature found")
        else:
            print("[!] No digital signature")

    def analyze_resources(self):
        print("[*] Resource Analysis")
        resources = self.binary.resources
        resource_types = {
            1: "CURSOR",
            2: "BITMAP",
            3: "ICON",
            4: "MENU",
            5: "DIALOG",
            6: "STRING",
            7: "FONTDIR",
            8: "FONT",
            9: "ACCELERATOR",
            10: "RCDATA",
            11: "MESSAGETABLE",
            12: "GROUP_CURSOR",
            14: "GROUP_ICON",
            16: "VERSION",
            17: "DLGINCLUDE",
            19: "PLUGPLAY",
            20: "VXD",
            21: "ANICURSOR",
            22: "ANIICON",
            23: "HTML",
            24: "MANIFEST"
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
                type_name = resource_types.get(resource_type.id, f"Unknown ({resource_type.id})")
                for resource_id in resource_type.childs:
                    for resource_lang in resource_id.childs:
                        print(f"   Resource type: {type_name} {resource_type.id}")
                        print(f"   Resource id: {resource_id.id}")
                        print(f"   Resource lang: {resource_lang.id}")
                        print(f"   Resource size: {len(resource_lang.content)} bytes")
                        
                        if len(resource_lang.content) > 1000000:
                            print(f"[!] Large resource detected: {len(resource_lang.content)} bytes")
                            
                        entropy = self.calculate_entropy(resource_lang.content)
                        if entropy > 7.0:
                            print(f"[!] High entropy resource: {entropy:.2f}")

                        # Extract resource to file
                        output_path = os.path.join(resources_dir, f"resource_{type_name}_{resource_id.id}.bin")
                        with open(output_path, 'wb') as f:
                            f.write(bytes(resource_lang.content))
                        print(f"   Extracted to: {output_path}")
        else:
            print("[!] No resources found")



class MachoSample(Sample):
    def analyze_functions(self):
        # Analyze functions and API calls
        for function in self.binary.symbols:
            print(f"Symbol: {function.name}")

    def analyze_metadata(self):
        # Analyze Mach-O headers
        print(f"Entry point: {self.binary.entrypoint}")

    def analyze_resources(self):
        # Mach-O typically doesn't have resources like PE
        print("No resources to analyze in Mach-O.")