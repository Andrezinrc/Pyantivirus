// Regra para detecção genérica de imagens maliciosas
rule Malicious_Image {
    strings:
        $image_magic1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 }
        $image_magic2 = { 00 01 00 01 ?? ?? ?? ?? 00 01 00 01 }
        $image_magic3 = { 01 00 01 00 ?? ?? ?? ?? 01 00 01 00 }
        $image_magic4 = { 01 01 01 01 ?? ?? ?? ?? 01 01 01 01 }
        $image_magic5 = { FF D8 FF E0 00 10 4A 46 49 46 00 01 }
        $image_magic6 = { FF D8 FF E1 ?? ?? 45 78 69 66 00 00 }
        $image_magic7 = { FF D8 FF E2 ?? ?? 49 49 2A 00 08 00 }
        $image_magic8 = { FF D8 FF E3 ?? ?? 4D 4D 00 2A 00 00 }
        $image_magic9 = { FF D8 FF E4 ?? ?? 44 41 53 48 00 00 }
        $image_magic10 = { FF D8 FF E5 ?? ?? 48 89 50 4E 47 0D }
        $image_magic11 = { FF D8 FF E6 ?? ?? 52 49 46 46 ?? ?? }
        $image_magic12 = { FF D8 FF E7 ?? ?? 00 00 00 00 00 00 }
        $image_magic13 = { FF D8 FF E8 ?? ?? 52 4D 4F 44 0A 00 }
        $image_magic14 = { FF D8 FF E9 ?? ?? 00 00 4A 46 49 46 }
        $image_magic15 = { FF D8 FF EA ?? ?? 00 00 4A 46 49 46 }
        $image_magic16 = { FF D8 FF EB ?? ?? 00 00 4A 46 49 46 }
        $image_magic17 = { FF D8 FF EC ?? ?? 00 00 00 00 00 00 }
        $image_magic18 = { FF D8 FF ED ?? ?? 00 00 00 00 00 00 }
        $image_magic19 = { FF D8 FF EE ?? ?? 00 00 00 00 00 00 }
        $image_magic20 = { FF D8 FF EF ?? ?? 00 00 00 00 00 00 }
        // Adicione mais strings conforme necessário...
    condition:
        any of ($image_magic*)
}
