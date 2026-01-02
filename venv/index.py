import ipaddress

def gerar_cgnat():

    print("--------- GERADOR DE CGNAT ------")

    public_prefix = input("Prefixo Publico (Ex: 143.255.137.0/24):") or "143.255.137.0/24"
    private_prefix = input("Prefixo Privado (Ex: 100.64.0.0/10):") or "100.64.0.0/10"
    clients_ignore = input("Clientes Por Ip Publico (Ex: 32): ") or "32"
    ignore_list = input("Nome da Lista: (EX: PPPoE_1):") or "PPPoE_1"
    usar_raw = input("Ativar no Track / RAW (s/n):").lower() == "s"
    usar_blackhole = input("Usar BlackHole? (s/n):").lower()  == "s"


    try:
        rede_pub = ipaddress.IPv4Network(public_prefix)
        ip_priv_atual = ipaddress.IPv4Address(private_prefix)
    except Exception as e:
        print(f"Erro nos IPs informados: {e}")
        return
    

    general_main_door = 1024
    
