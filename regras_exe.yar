rule Malicious_EXE_1 {
    strings:
        $exe_signature = {4D 5A} // Assinatura do formato PE
    condition:
        $exe_signature
}

rule Malicious_EXE_2 {
    strings:
        $exe_signature = {4D 5A 90 00 03 00 00 00} // Assinatura do formato PE
    condition:
        $exe_signature
}

