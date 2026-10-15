import subprocess 

class Run():
    def runnner(target):
        command = [
            "nmap",
            "-sS",                  # SYN Scan (Port Tespiti)
            "-sV",                  # Service / Version Detection
            "-O",                   # OS Detection
            "--traceroute",         # Topoloji ve Hop Analizi
            "-oX=scan.xml",     # XML Çıktı Dosyası
            target
        ]
        try:
            #running nmap sometimes wants a admin privilige
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            print(f"[+] scan is complete output file scan.xml")
            return True

        except subprocess.CalledProcessError as e:
            print(f"[!] Nmap running error: {e.stderr}")
            return False