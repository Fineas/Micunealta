import argparse
import os
import subprocess
from sample import ElfSample, PeSample, MachoSample

# -------------------------------
# GLOBALS
# -------------------------------
json_dump = False
pdf_dump = False

# -------------------------------
# METHODS
# -------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(description="Micunealta")
    parser.add_argument('--bin', required=True, help='Path to the executable file')
    parser.add_argument('--json', required=False, action='store_true', help='Dump results to JSON')
    parser.add_argument('--pdf', required=False, action='store_true', help='Dump results to PDF')
    return parser.parse_args()

def check_file_exists(filepath):
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"[!] The file {filepath} does not exist.")
    
def get_file_type(filepath):
    result = subprocess.run(['file', filepath], capture_output=True, text=True)
    return result.stdout
    
def main():
    global json_dump, pdf_dump

    args = parse_arguments()
    filepath = args.bin
    if args.json:
        json_dump = True
    if args.pdf:
        pdf_dump = True

    # -------------------------------
    # [1] Ensure the File Exists
    check_file_exists(filepath)

    # -------------------------------
    # [2] Determine the File Type
    file_info = get_file_type(filepath)
    print(f"[*] File info: {file_info}")

    # -------------------------------
    # [3] Initialize and Load the Sample
    if 'ELF' in file_info:
        sample = ElfSample(filepath)
    elif 'PE32' in file_info or 'PE32+' in file_info:
        sample = PeSample(filepath)
    elif 'Mach-O' in file_info:
        sample = MachoSample(filepath)
    else:
        raise ValueError("[!] Unsupported file type")

    # -------------------------------
    # [4] Static Analysis
    sample.static_analysis()

    # -------------------------------
    # [5] Dynamic Analysis
    sample.dynamic_analysis()

    # -------------------------------
    # [6] Dump Results
    sample.results(json_dump, pdf_dump)

if __name__ == "__main__":
    main()