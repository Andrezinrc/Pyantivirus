rule PDF_Malicioso {
    strings:
        $pdf_magic = { 25 50 44 46 }  // Assinatura de um arquivo PDF:
        $string_suspeita1 = "javascript" nocase
        $string_suspeita2 = "action" nocase
        $string_suspeita3 = "openaction" nocase
        $string_suspeita4 = "embeddedfile" nocase
        $string_suspeita5 = "exe" nocase
        $string_suspeita6 = "payload" nocase
        $string_suspeita7 = "exploit" nocase
        $string_suspeita8 = "virus" nocase
        $string_suspeita9 = "trojan" nocase
        $string_suspeita10 = "worm" nocase
        $string_suspeita11 = "malware" nocase
        $string_suspeita12 = "ransomware" nocase
        $string_suspeita13 = "backdoor" nocase
        $string_suspeita14 = "spyware" nocase
        $string_suspeita15 = "keylogger" nocase
        $string_suspeita16 = "phishing" nocase
        $string_suspeita17 = "rootkit" nocase
        $string_suspeita18 = "adware" nocase
        $string_suspeita19 = "botnet" nocase
        $string_suspeita20 = "exploitation" nocase
        // Adicione mais strings suspeitas conforme necessário
        $string_suspeita21 = "vulnerability" nocase
        $string_suspeita22 = "payload delivery" nocase
        $string_suspeita23 = "malicious payload" nocase
        $string_suspeita24 = "remote access" nocase
        $string_suspeita25 = "command and control" nocase
        $string_suspeita26 = "information stealing" nocase
        $string_suspeita27 = "credential stealing" nocase
        $string_suspeita28 = "identity theft" nocase
        $string_suspeita29 = "credit card theft" nocase
        $string_suspeita30 = "banking fraud" nocase
        $string_suspeita31 = "phishing site" nocase
        $string_suspeita32 = "malicious website" nocase
        $string_suspeita33 = "exploit code" nocase
        $string_suspeita34 = "data breach" nocase
        $string_suspeita35 = "ransom note" nocase
        $string_suspeita36 = "payload execution" nocase
        $string_suspeita37 = "system compromise" nocase
        $string_suspeita38 = "root access" nocase
        $string_suspeita39 = "sensitive data exfiltration" nocase
        $string_suspeita40 = "system hijack" nocase
        $string_suspeita41 = "exploit code" nocase
        $string_suspeita42 = "malicious behavior" nocase
        $string_suspeita43 = "malicious activity" nocase
        $string_suspeita44 = "malicious operation" nocase
        $string_suspeita45 = "malicious intent" nocase
        $string_suspeita46 = "malicious purpose" nocase
        $string_suspeita47 = "malicious functionality" nocase
        $string_suspeita48 = "malicious capability" nocase
        $string_suspeita49 = "malicious action" nocase
        $string_suspeita50 = "malicious command" nocase
        $string_suspeita51 = "malicious communication" nocase
        $string_suspeita52 = "malicious operation" nocase
        $string_suspeita53 = "malicious payload" nocase
        $string_suspeita54 = "malicious traffic" nocase
        $string_suspeita55 = "malicious network" nocase
        $string_suspeita56 = "malicious link" nocase
        $string_suspeita57 = "malicious connection" nocase
        $string_suspeita58 = "malicious request" nocase
        $string_suspeita59 = "malicious activity" nocase
        $string_suspeita60 = "malicious behavior" nocase
        $string_suspeita61 = "malicious software" nocase
        $string_suspeita62 = "malicious tool" nocase
        $string_suspeita63 = "malicious file" nocase
        $string_suspeita64 = "malicious program" nocase
        $string_suspeita65 = "malicious script" nocase
        $string_suspeita66 = "malicious module" nocase
        $string_suspeita67 = "malicious function" nocase
        $string_suspeita68 = "malicious service" nocase
        $string_suspeita69 = "malicious process" nocase
        $string_suspeita70 = "malicious thread" nocase
        $string_suspeita71 = "malicious code" nocase
        $string_suspeita72 = "malicious string" nocase
        $string_suspeita73 = "malicious value" nocase
        $string_suspeita74 = "malicious data" nocase
        $string_suspeita75 = "malicious instruction" nocase
        $string_suspeita76 = "malicious operation" nocase
        $string_suspeita77 = "malicious behavior" nocase
        $string_suspeita78 = "malicious action" nocase
        $string_suspeita79 = "malicious activity" nocase
        $string_suspeita80 = "malicious behavior" nocase
        $string_suspeita81 = "malicious operation" nocase
        $string_suspeita82 = "malicious intent" nocase
        $string_suspeita83 = "malicious purpose" nocase
        $string_suspeita84 = "malicious functionality" nocase
        $string_suspeita85 = "malicious capability" nocase
        $string_suspeita86 = "malicious action" nocase
        $string_suspeita87 = "malicious command" nocase
        $string_suspeita88 = "malicious communication" nocase
        $string_suspeita89 = "malicious operation" nocase
        $string_suspeita90 = "malicious payload" nocase
        $string_suspeita91 = "malicious traffic" nocase
        $string_suspeita92 = "malicious network" nocase
        $string_suspeita93 = "malicious link" nocase
        $string_suspeita94 = "malicious connection" nocase
        $string_suspeita95 = "malicious request" nocase
        $string_suspeita96 = "malicious activity" nocase
        $string_suspeita97 = "malicious behavior" nocase
        $string_suspeita98 = "malicious software" nocase
        $string_suspeita99 = "malicious tool" nocase
        $string_suspeita100 = "malicious file" nocase
        $string_suspeita101 = "malicious program" nocase
        $string_suspeita102 = "malicious script" nocase
        $string_suspeita103 = "malicious module" nocase
        $string_suspeita104 = "malicious function" nocase
        $string_suspeita105 = "malicious service" nocase
        $string_suspeita106 = "malicious process" nocase
        $string_suspeita107 = "malicious thread" nocase
        $string_suspeita108 = "malicious code" nocase
        $string_suspeita109 = "malicious string" nocase
        $string_suspeita110 = "malicious value" nocase
        $string_suspeita111 = "malicious data" nocase
        $string_suspeita112 = "malicious instruction" nocase
        $string_suspeita113 = "malicious operation" nocase
        $string_suspeita114 = "malicious behavior" nocase
        $string_suspeita115 = "malicious action" nocase
        $string_suspeita116 = "malicious activity" nocase
        $string_suspeita117 = "malicious behavior" nocase
        $string_suspeita118 = "malicious operation" nocase
        $string_suspeita119 = "malicious intent" nocase
        $string_suspeita120 = "malicious purpose" nocase
        $string_suspeita121 = "malicious functionality" nocase
        $string_suspeita122 = "malicious capability" nocase
        $string_suspeita123 = "malicious action" nocase
        $string_suspeita124 = "malicious command" nocase
        $string_suspeita125 = "malicious communication" nocase
        $string_suspeita126 = "malicious operation" nocase
        $string_suspeita127 = "malicious payload" nocase
        $string_suspeita128 = "malicious traffic" nocase
        $string_suspeita129 = "malicious network" nocase
        $string_suspeita130 = "malicious link" nocase
        $string_suspeita131 = "malicious connection" nocase
        $string_suspeita132 = "malicious request" nocase
        $string_suspeita133 = "malicious activity" nocase
        $string_suspeita134 = "malicious behavior" nocase
        $string_suspeita135 = "malicious software" nocase
        $string_suspeita136 = "malicious tool" nocase
        $string_suspeita137 = "malicious file" nocase
        $string_suspeita138 = "malicious program" nocase
        $string_suspeita139 = "malicious script" nocase
        $string_suspeita140 = "malicious module" nocase
        $string_suspeita141 = "malicious function" nocase
        $string_suspeita142 = "malicious service" nocase
        $string_suspeita143 = "malicious process" nocase
        $string_suspeita144 = "malicious thread" nocase
        $string_suspeita145 = "malicious code" nocase
        $string_suspeita146 = "malicious string" nocase
        $string_suspeita147 = "malicious value" nocase
        $string_suspeita148 = "malicious data" nocase
        $string_suspeita149 = "malicious instruction" nocase
        $string_suspeita150 = "malicious operation" nocase
    condition:
      $pdf_magic at 0 or any of ($string_suspeita*)
}
