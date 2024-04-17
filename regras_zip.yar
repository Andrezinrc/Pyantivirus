// Regras para detecção de arquivos ZIP maliciosos

rule Malicious_ZIP_1 {
    strings:
        $zip_signature = {50 4B 03 04}
    condition:
        $zip_signature
}

rule Malicious_ZIP_2 {
    strings:
        $zip_signature = {50 4B 05 06}
    condition:
        $zip_signature
}

