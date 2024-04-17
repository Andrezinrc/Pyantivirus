rule URL_Maliciosa {
    strings:
        $url1 = "http://phishing.com" nocase
        $url2 = "https://malware.com" nocase
        $url3 = "http://bit.ly/" nocase
        $url4 = "http://evilsite.net" nocase
        $url5 = "http://fakebank.com" nocase
        $url6 = "http://suspicious.net" nocase
        $url7 = "http://fraudulent.biz" nocase
        $url8 = "http://scam.org" nocase
        $url9 = "http://dangerous.info" nocase
        $url10 = "http://deceptive.xyz" nocase
        $url11 = "http://malicious.site" nocase
        $url12 = "http://lee-phishing.com" nocase
        $url13 = "http://lee-malware.net" nocase
        $url14 = "http://lee-fakebank.com" nocase
        $url15 = "http://lee-fraudulent.biz" nocase
        $url16 = ".trycloudflare.com" nocase
        $url17 = "http://evilserver.com" nocase
        $url18 = "http://viruswebsite.org" nocase
        $url19 = "http://phishingscam.net" nocase
        $url20 = "http://dangerousmalware.net" nocase
        $url21 = "http://malicioussite.org" nocase
        $url22 = "http://scammingpage.com" nocase
        $url23 = "http://fraudulentwebsite.biz" nocase
        $url24 = "http://fakebanking.org" nocase
        $url25 = "http://fakesurvey.com" nocase
        $url26 = "http://phishingattack.net" nocase
        $url27 = "http://malwareattack.com" nocase
        $url28 = "http://phishingsite.net" nocase
        $url29 = "http://fraudulentbank.org" nocase
        $url30 = "http://scammingsite.com" nocase
        $url31 = "http://evilphishing.biz" nocase
        $url32 = "http://virusattack.org" nocase
        $url33 = "http://fraudulentpage.com" nocase
        $url34 = "http://malicioussurvey.net" nocase
        $url35 = "http://scamalert.biz" nocase
        $url36 = "http://fakewebsite.org" nocase
        $url37 = "http://maliciousbanking.com" nocase
        $url38 = "http://fakephishingpage.biz" nocase
        $url39 = "http://evilphishingscam.org" nocase
        $url40 = "http://scamsurvey.net" nocase
        $url41 = "http://fraudulentalert.com" nocase
        $url42 = "http://phishingbank.biz" nocase
        $url43 = "http://viruswarning.org" nocase
        $url44 = "http://malwarewarning.com" nocase
        $url45 = "http://phishingsurvey.org" nocase
        $url46 = "http://malicioussitealert.biz" nocase
        $url47 = "http://scamwebsitewarning.com" nocase
        $url48 = "http://fakebankingalert.org" nocase
        $url49 = "http://evilphishingwarning.biz" nocase
        $url50 = "http://virusalertsurvey.net" nocase
        $url51 = "free@" nocase
        $url52 = "-" nocase
        // Adicione mais URLs maliciosas conforme necessário
        $url53 = "http://phishingsite.biz" nocase
        $url54 = "http://malwarewarning.org" nocase
        $url55 = "http://scamsurvey.biz" nocase
        $url56 = "http://fraudulentalert.org" nocase
        $url57 = "http://phishingbanking.com" nocase
        $url58 = "http://viruswarning.biz" nocase
        $url59 = "http://malwarealert.org" nocase
        $url60 = "http://phishingsitealert.com" nocase
        $url61 = "http://scamwebsitewarning.biz" nocase
        $url62 = "http://fakebankingalert.com" nocase
        $url63 = "http://evilphishingwarning.org" nocase
        $url64 = "http://virusalertsurvey.biz" nocase
        $url65 = "http://phishingscam.com" nocase
        $url66 = "http://malwarescam.org" nocase
        $url67 = "http://scamalertsurvey.biz" nocase
        $url68 = "http://fraudulentbankingalert.com" nocase
        $url69 = "http://phishingattackwarning.org" nocase
        $url70 = "http://maliciousbankingscam.biz" nocase
        $url71 = "http://scamwebsitealert.com" nocase
        $url72 = "http://fakebankingscamwarning.org" nocase
        $url73 = "http://evilphishingsitealert.biz" nocase
        $url74 = "http://virusattackwarning.com" nocase
        $url75 = "http://phishingsurveyalert.org" nocase
        $url76 = "http://maliciousbankingalert.biz" nocase
        $url77 = "http://scamwebsitewarning.org" nocase
        $url78 = "http://fraudulentbankingalert.biz" nocase
        $url79 = "http://phishingscamwarning.org" nocase
        $url80 = "http://maliciouswebsitewarning.biz" nocase
        $url81 = "http://scamwebsitewarning.org" nocase
        $url82 = "http://evilphishingalert.biz" nocase
        $url83 = "http://viruswarningalert.org" nocase
        $url84 = "http://phishingsitealert.biz" nocase
        $url85 = "http://malwarescamalert.org" nocase
        $url86 = "http://scamalertsurvey.biz" nocase
        $url87 = "http://fraudulentwebsitealert.org" nocase
        $url88 = "http://phishingbankingalert.biz" nocase
        $url89 = "http://viruswarningalert.org" nocase
        $url90 = "http://malwarewarningalert.biz" nocase
        $url91 = "http://phishingsurveyalert.org" nocase
        $url92 = "http://malicioussitealert.biz" nocase
        $url93 = "http://scamwebsitewarning.biz" nocase
        $url94 = "http://fakebankingalert.biz" nocase
        $url95 = "http://evilphishingalert.org" nocase
        $url96 = "http://viruswarningalert.biz" nocase
        $url97 = "http://phishingscamalert.org" nocase
        $url98 = "http://malwarewarningalert.biz" nocase
        $url99 = "http://scamwebsitewarning.org" nocase
        $url100 = "http://fraudulentbankingalert.biz" nocase
    condition:
      any of them
}
// Domínios suspeitos
rule Malicious_URL_Domain {
    strings:
        $domain1 = "malware.com"
        $domain2 = "phishing.net"
    condition:
        any of ($domain*)
}

// Padrões de caminhos de URL
rule Malicious_URL_Path {
    strings:
        $path1 = "install.exe"
        $path2 = "banking-login"
    condition:
        any of ($path*)
}

// Padrões de query strings
rule Malicious_URL_QueryString {
    strings:
        $query1 = "?id=123&token=abc"
        $query2 = "?cmd=execute&payload=malware"
    condition:
        any of ($query*)
}

// Padrões de protocolos suspeitos
rule Malicious_URL_Protocol {
    strings:
        $protocol1 = "ftp://"
        $protocol2 = "file://"
    condition:
        any of ($protocol*)
}

// Padrões de IPs suspeitos
rule Malicious_URL_IP {
    strings:
        $ip1 = /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/  // Detecta qualquer sequência de números no formato de endereço IP
        $ip2 = /(?:\d{1,3}\.){3}\d{1,3}/  // Outra forma de detectar endereços IP
    condition:
        any of ($ip*)
}
