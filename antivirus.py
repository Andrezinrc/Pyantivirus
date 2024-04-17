import os
import yara
import subprocess
from colorama import Fore, Style
from tqdm import tqdm
import socket
import requests
import random
from time import sleep
import psutil
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import re
import nmap


caminho_regras_apk = "regras_apk.yar"
caminho_regras_imagem = "regras_imagem.yar"
caminho_regras_exe = "regras_exe.yar"
caminho_regras_zip = "regras_zip.yar"
caminho_regras_url = "regras_url.yar"


try:
    regra_compilada_apk = yara.compile(filepath=caminho_regras_apk)
    regra_compilada_imagem = yara.compile(filepath=caminho_regras_imagem)
    regra_compilada_exe = yara.compile(filepath=caminho_regras_exe)
    regra_compilada_zip = yara.compile(filepath=caminho_regras_zip)
    regra_compilada_url = yara.compile(filepath=caminho_regras_url)
except yara.SyntaxError as e:
    print("Erro de sintaxe ao compilar regras YARA:", e)
except FileNotFoundError:
    print("Arquivo de regras YARA não encontrado:", caminho_regras_apk)
    
caminho_raiz_android = "/storage/emulated/0"

def verificar_malwares(caminho_raiz, tipos_malwares):
    arquivos_maliciosos_encontrados = []
    arquivos_verificados = set()

    def verificar_arquivo(arquivo_path, tipo_malware):
        nonlocal arquivos_maliciosos_encontrados

        if arquivo_path in arquivos_verificados:
            return

        arquivos_verificados.add(arquivo_path)

        if arquivo_path.endswith(tipo_malware['extensao']):

            correspondencias = tipo_malware['regra'].match(arquivo_path)

            if correspondencias:
                for match in correspondencias:
                    tipo_malware_encontrado = match.rule
                    arquivo_malicioso = {
                        "path": arquivo_path,
                        "tipo_malware": tipo_malware_encontrado
                    }
                    arquivos_maliciosos_encontrados.append(arquivo_malicioso)

    def verificar_diretorio(diretorio):
        total_arquivos = sum(len(files) for _, _, files in os.walk(diretorio))
        with tqdm(total=total_arquivos, desc="└── Verificando arquivos: ") as pbar:
            for root, _, files in os.walk(diretorio):
                for nome_arquivo in files:
                    caminho_arquivo = os.path.join(root, nome_arquivo)
                    for tipo_malware in tipos_malwares:
                        verificar_arquivo(caminho_arquivo, tipo_malware)
                    sleep(0.1)
                    pbar.update(1)
                    print(Fore.RED + "└──", nome_arquivo)

    verificar_diretorio(caminho_raiz)

    if arquivos_maliciosos_encontrados:
        print(Fore.RED + "└── Encontramos alguns riscos à segurança:")
        for arquivo_malicioso in arquivos_maliciosos_encontrados:
            print(f"└── Caminho do arquivo: {arquivo_malicioso['path']}")
            print(f"└── Tipo de malware: {arquivo_malicioso['tipo_malware']}")
        excluir = input("└── Deseja excluir os arquivos maliciosos? (s/n): ")
        if excluir.lower() == 's':
            for arquivo in arquivos_maliciosos_encontrados:
                os.remove(arquivo['path'])
            print(Fore.GREEN + "Arquivos excluídos com sucesso. Você está seguro.")
            sleep(4)
            os.system("clear")
        else:
            print(Fore.RED + "└── Nenhum arquivo foi excluído. Seu dispositivo ainda está em risco!")
            sleep(4)
            os.system("clear")
    else:
        print(Fore.GREEN + "└── Nenhum arquivo malicioso encontrado.")
        sleep(4)
        os.system("clear")


caminho_raiz = "/storage/emulated/0/"
tipos_malwares = [
    {
        "nome": "APK",
        "extensao": ".apk",
        "regra": regra_compilada_apk  # Sua regra YARA para APK
    },
    {
        "nome": "Exe",
        "extensao": ".exe",
        "regra": regra_compilada_exe  # Exemplo de regra YARA para executáveis
    },
    {
        "nome": "Imagem",
        "extensao": ".jpg",
        "regra": regra_compilada_imagem  # Sua regra YARA para imagens
    },
    {
        "nome": "Zip",
        "extensao": ".zip",
        "regra": regra_compilada_zip 
    },
]

def verificar_url():
    url = input("Digite a URL para verificar se é maliciosa: ")
    correspondencias = regra_compilada_url.match(data=url)

    if correspondencias:
        print(Fore.RED + "└── URL maliciosa encontrada.")
    else:
        print(Fore.GREEN + "└── A URL parece ser segura.")

def listar_conexoes():
    try:
        saida = subprocess.check_output(['netstat', '-atu'])
        linhas = saida.decode('utf-8').split('\n')

        # Imprimir as conexões
        if linhas:
            print("Listagem das conexões ativas:")
            print(Fore.GREEN + "└── {:<20} {:<20} {:<20} {:<20}".format("Proto", "Endereço Local", "Endereço Remoto", "Estado"))
            print("-" * 80)
            for linha in linhas[2:]:
                campos = linha.split()
                if len(campos) >= 5:
                    proto = campos[0]
                    endereco_local = campos[3]
                    endereco_remoto = campos[4]
                    estado = campos[5] if len(campos) >= 6 else "-"
                    print("{:<20} {:<20} {:<20} {:<20}".format(proto, endereco_local, endereco_remoto, estado))
                    sleep(0.5)
        else:
            print("Nenhuma conexão encontrada.")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar o comando netstat: {e}")
    except Exception as e:
        print(f"Ocorreu um erro ao listar as conexões: {e}")


def verificar_conexoes_suspeitas(ip_local):
    try:
        saida = subprocess.check_output(['netstat', '-atu'])
        linhas = saida.decode('utf-8').split('\n')
        conexoes_suspeitas = []
        interceptacao_de_rede = False
        conexoes_nao_autorizadas = []

        for linha in linhas:
            if "ESTABLISHED" in linha:
                partes = linha.split()
                endereco_local = partes[3].split(":")[0]
                endereco_remoto = partes[4].split(":")[0]

                if endereco_remoto.startswith("192.168.1") and endereco_local == ip_local:
                    conexoes_suspeitas.append(endereco_remoto)

                processo = partes[-1]

                if processo.startswith("sudo") or processo.startswith("root"):
                    interceptacao_de_rede = True

            # Verifica conexões em portas não atribuídas para UDP
            elif "UNKNOWN" in linha and "udp" in linha:
                partes = linha.split()
                endereco_local = partes[3].split(":")[0]
                endereco_remoto = partes[4].split(":")[0]

                if endereco_local == ip_local:
                    conexoes_nao_autorizadas.append(endereco_remoto)

        if conexoes_suspeitas:
            print(Fore.RED + f"IPs locais suspeitos conectando-se ({len(conexoes_suspeitas)}):")
            for ip in conexoes_suspeitas:
                print(ip)
            print(Style.RESET_ALL)
        else:
            print(Fore.GREEN + "Nenhuma conexão suspeita encontrada.")

        if conexoes_nao_autorizadas:
            print(Fore.RED + f"Conexões não autorizadas identificadas ({len(conexoes_nao_autorizadas)}):")
            for ip in conexoes_nao_autorizadas:
                print(ip)
            print(Style.RESET_ALL)

        if interceptacao_de_rede:
            print(Fore.RED + "Sinais de interceptação de rede detectados.")
        else:
            print(Fore.GREEN + "Nenhum sinal de interceptação de rede detectado.")

    except Exception as e:
        print(Fore.RED + f"Ocorreu um erro ao verificar as conexões: {e}")

def verifica_numero(numero):
    try:
        parsed_numero = phonenumbers.parse(numero, None)
    except phonenumbers.phonenumberutil.NumberParseException:
        print(Fore.RED + " [-] Número inválido")
        return

    if not phonenumbers.is_valid_number(parsed_numero):
        print(Fore.RED + " [-] Número inválido")
        return

    print(Fore.RED + "\n [>] Informações sobre o número de telefone:")

    # Operadora de telefonia
    operadora = carrier.name_for_number(parsed_numero, "pt")
    if operadora:
        print(Fore.RED + f"  ├── Operadora: {operadora}")

    # País
    pais = geocoder.country_name_for_number(parsed_numero, "pt")
    if pais:
        print(Fore.RED + f"  ├── País: {pais}")

    # Tipo de linha
    tipo_linha = phonenumbers.number_type(parsed_numero)
    if tipo_linha:
        tipo_linha_descricao = phonenumbers.number_type(parsed_numero)
        print(Fore.RED + f"  ├── Tipo de Linha: {tipo_linha_descricao}")

    # Estado
    estado = geocoder.description_for_number(parsed_numero, "pt")
    if estado:
        print(Fore.RED + f"  ├── Estado: {estado}")

    # Zona Horária
    zona_horaria = timezone.time_zones_for_number(parsed_numero)
    if zona_horaria:
        print(Fore.RED + f"  ├── Fuso Horário: {zona_horaria[0]}")

    # Indicação de Roaming Internacional
    if phonenumbers.is_possible_number(parsed_numero):
        print(Fore.RED + "  ├── Roaming Internacional: Possível")
    else:
        print(Fore.RED + "  ├── Roaming Internacional: Não possível")

    # Formato Internacional
    formato_internacional = phonenumbers.format_number(parsed_numero, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    print(Fore.RED + f"  ├── Formato Internacional: {formato_internacional}")

    # Validade do Número
    razao_validade = phonenumbers.is_possible_number_with_reason(parsed_numero)
    if razao_validade == phonenumbers.ValidationResult.IS_POSSIBLE:
        print(Fore.RED + "  ├── Validade do Número: Possível")
    elif razao_validade == phonenumbers.ValidationResult.INVALID_COUNTRY_CODE:
        print(Fore.RED + "  ├── Validade do Número: Código de País Inválido")
    elif razao_validade == phonenumbers.ValidationResult.TOO_SHORT:
        print(Fore.RED + "  ├── Validade do Número: Número Muito Curto")
    elif razao_validade == phonenumbers.ValidationResult.TOO_LONG:
        print(Fore.RED + "  ├── Validade do Número: Número Muito Longo")
    else:
        print(Fore.RED + "  ├── Validade do Número: Desconhecido")


def busca_spam(numero):
    verifica_numero(numero)
    print(Fore.RED + "Verificação de Spam")

    url = f"https://spamcalls.net/pt/numero/{numero}"

    user_agents = ler_agentes_usuario()

    resposta = requests.get(url, headers={'user-agent': random.choice(user_agents)})
    if resposta.status_code == 200:
        print(Fore.RED + "└── Provável spam")
    else:
        print(Fore.GREEN + "└── Não é spam")

def print_banner():
    print(Fore.RED + "                                                                      ")
    print(Fore.RED + "▄▄▄      ███▄    █▄▄▄█████▓██▓    ██▒   █▓██▓██▀███  █    ██  ██████  ")
    print(Fore.RED + "▒████▄    ██ ▀█   █▓  ██▒ ▓▓██▒   ▓██░   █▓██▓██ ▒ ██▒██  ▓██▒██    ▒ ")
    print(Fore.RED + "▒██  ▀█▄ ▓██  ▀█ ██▒ ▓██░ ▒▒██▒    ▓██  █▒▒██▓██ ░▄█ ▓██  ▒██░ ▓██▄   ")
    print(Fore.RED + "░██▄▄▄▄██▓██▒  ▐▌██░ ▓██▓ ░░██░     ▒██ █░░██▒██▀▀█▄ ▓▓█  ░██░ ▒   ██▒")
    print(Fore.RED + " ▓█   ▓██▒██░   ▓██░ ▒██▒ ░░██░      ▒▀█░ ░██░██▓ ▒██▒▒█████▓▒██████▒▒")
    print(" ▒▒   ▓▒█░ ▒░   ▒ ▒  ▒ ░░  ░▓        ░ ▐░ ░▓ ░ ▒▓ ░▒▓░▒▓▒ ▒ ▒▒ ▒▓▒ ▒ ░")
    print(Fore.RED + "  ▒   ▒▒ ░ ░░   ░ ▒░   ░    ▒ ░      ░ ░░  ▒ ░ ░▒ ░ ▒░░▒░ ░ ░░ ░▒  ░ ░")
    print(Fore.RED + "  ░   ▒     ░   ░ ░  ░      ▒ ░        ░░  ▒ ░ ░░   ░ ░░░ ░ ░░  ░  ░  ")
    print(Fore.RED + "      ░  ░        ░         ░           ░  ░    ░       ░          ░  ")
    print(Fore.RED + "                                       ░                              ")

def menu():
    print_banner()
    print(Fore.RED + "└── 1. Varrer o celular em busca de arquivos maliciosos.  ")
    print(Fore.RED + "└── 2. Verificar se uma URL é maliciosa.                      ")
    print(Fore.RED + "└── 3. Verificar conexões de rede suspeitas.                  ")
    print(Fore.RED + "└── 4. Verificar se o número é considerado spammer.          ")
    
    opcao = input(Fore.RED + "└── Escolha a opção: ")

    if opcao == "1":
        verificar_malwares(caminho_raiz, tipos_malwares)
    elif opcao == "2":
        verificar_url()
    elif opcao == "3":
        listar_conexoes()
        verificar_conexoes_suspeitas("ip")
    elif opcao == "4":
        numero_telefone = input(Fore.RED + "Digite o número de telefone para verificar se é spam: ")
        busca_spam(numero_telefone)
    else:
        print(Fore.RED + "└── Opção inválida. Por favor, escolha 1, 2, 3 ou 4.")

menu()

